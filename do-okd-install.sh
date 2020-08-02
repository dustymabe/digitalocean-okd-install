#!/bin/bash
set -eu -o pipefail

# Load the environment variables that control the behavior of this
# script.
source ./config

# Returns a string representing the image ID for a given name.
# Returns empty string if none exists
get_image_from_name() {
    doctl compute image list-user -o json | \
        jq -r ".[] | select(.name == \"${DROPLET_IMAGE_NAME}\").id"
}

# https://docs.fedoraproject.org/en-US/fedora-coreos/provisioning-digitalocean/
create_image_if_not_exists() {
    echo -e "\nCreating custom image ${DROPLET_IMAGE_NAME}.\n"

    # if image exists, return
    if [ "$(get_image_from_name)" != "" ]; then
        echo "Image with name already exists. Skipping image creation."
        return 0
    fi

    # Create the image from the URL
    doctl compute image create         \
        $DROPLET_IMAGE_NAME            \
        --region $DIGITAL_OCEAN_REGION \
        --image-url $FCOS_IMAGE_URL >/dev/null

    # Wait for the image to finish being created
    for x in {0..100}; do
        if [ "$(get_image_from_name)" != "" ]; then
            return 0 # We're done
        fi
        echo "Waiting for image to finish creation..."
        sleep 10
    done

    echo "Image never finished being created." >&2
    return 1
}

generate_manifests() {
    echo -e "\nGenerating manifests/configs for install.\n"

    # Clear out old generated files
    rm -rf ./generated-files/ && mkdir ./generated-files

    # Copy install-config in place (remove comments) and replace tokens
    # in the template with the actual values we want to use.
    grep -v '^#' resources/install-config.yaml.in > generated-files/install-config.yaml
    for token in BASEDOMAIN      \
                 CLUSTERNAME     \
                 NUM_OKD_WORKERS \
                 NUM_OKD_CONTROL_PLANE;
    do
        sed -i "s/$token/${!token}/" generated-files/install-config.yaml
    done

    # Generate manifests and create the ignition configs from that.
    openshift-install create manifests --dir=generated-files
    openshift-install create ignition-configs --dir=generated-files

    # Copy the bootstrap ignition file to a remote location so we can
    # pull from it on startup. It's too large to fit in user-data.
    sum=$(sha512sum ./generated-files/bootstrap.ign | cut -d ' ' -f 1)
    aws --endpoint-url $SPACES_ENDPOINT s3 cp \
        ./generated-files/bootstrap.ign "${SPACES_BUCKET}/bootstrap.ign" >/dev/null

    # Generate a pre-signed URL to use to grab the config. Ensures
    # only we can grab it and it expires after short period of time.
    url=$(aws --endpoint-url $SPACES_ENDPOINT s3 presign \
                "${SPACES_BUCKET}/bootstrap.ign" --expires-in 300)
    # backslash escape the '&' chars in the URL since '&' is interpreted by sed
    escapedurl=${url//&/\\&}

    # Add tweaks to the bootstrap ignition and a pointer to the remote bootstrap
    cat resources/fcct-bootstrap.yaml     | \
        sed "s|SHA512|sha512-${sum}|"     | \
        sed "s|SOURCE_URL|${escapedurl}|" | \
        fcct -o ./generated-files/bootstrap-processed.ign

    # Add tweaks to the control plane config
    cat resources/fcct-control-plane.yaml | \
        fcct -d ./ -o ./generated-files/control-plane-processed.ign

    # Add tweaks to the worker config
    cat resources/fcct-worker.yaml | \
        fcct -d ./ -o ./generated-files/worker-processed.ign
}

# returns if we have any worker nodes or not to create
have_workers() {
    if [ $NUM_OKD_WORKERS -gt 0 ]; then
        return 0
    else
        return 1
    fi
}

# prints a sequence of numbers to iterate over from 0 to N-1
# for the number of control plane nodes
control_plane_num_sequence() {
    seq 0 $((NUM_OKD_CONTROL_PLANE-1))
}

# prints a sequence of numbers to iterate over from 0 to N-1
# for the number of worker nodes
worker_num_sequence() {
    seq 0 $((NUM_OKD_WORKERS-1))
}

create_droplets() {
    echo -e "\nCreating droplets.\n"

    local common_options=''
    common_options+="--region $DIGITAL_OCEAN_REGION "
    common_options+="--ssh-keys $DROPLET_KEYPAIR "
    common_options+="--size $DROPLET_SIZE "
    common_options+="--image $(get_image_from_name) "
    common_options+="--vpc-uuid $(get_vpc_id) "

    # Create bootstrap node
    doctl compute droplet create bootstrap $common_options        \
        --tag-names "${ALL_DROPLETS_TAG},${CONTROL_DROPLETS_TAG}" \
        --user-data-file generated-files/bootstrap-processed.ign >/dev/null

    # Create control plane nodes
    for num in $(control_plane_num_sequence); do
        doctl compute droplet create "okd-control-${num}" $common_options \
            --tag-names "${ALL_DROPLETS_TAG},${CONTROL_DROPLETS_TAG}" \
            --user-data-file generated-files/control-plane-processed.ign >/dev/null
    done

    # Create worker nodes
    if have_workers; then
        for num in $(worker_num_sequence); do
            doctl compute droplet create "okd-worker-${num}" $common_options \
                --tag-names "${ALL_DROPLETS_TAG},${WORKER_DROPLETS_TAG}" \
                --user-data-file ./generated-files/worker-processed.ign >/dev/null
        done
    fi

}

create_load_balancer() {
    echo -e "\nCreating load-balancer.\n"
    # Create a load balancer that passes through port 80 443 6443 22623 traffic.
    # to all droplets tagged as control plane nodes.
    # https://www.digitalocean.com/community/tutorials/how-to-work-with-digitalocean-load-balancers-using-doctl
    check="protocol:tcp,port:6443,path:,check_interval_seconds:10,response_timeout_seconds:10,healthy_threshold:2,unhealthy_threshold:10"
    rules=''
    for port in 80 443 6443 22623; do
        rules+="entry_protocol:tcp,entry_port:${port},target_protocol:tcp,target_port:${port},certificate_id:,tls_passthrough:false "
    done
    rules="${rules:0:-1}" # pull off trailing space
    doctl compute load-balancer create   \
        --name $DOMAIN                   \
        --region $DIGITAL_OCEAN_REGION   \
        --vpc-uuid $(get_vpc_id)         \
        --tag-name $CONTROL_DROPLETS_TAG \
        --health-check "${check}"        \
        --forwarding-rules "${rules}" >/dev/null
    # wait for load balancer to come up
    ip='null'
    while [ "${ip}" == 'null' ]; do
        echo "Waiting for load balancer to come up..."
        sleep 5
        ip=$(get_load_balancer_ip)
    done
}

get_load_balancer_id() {
    doctl compute load-balancer list -o json | \
        jq -r ".[] | select(.name == \"${DOMAIN}\").id"
}

get_load_balancer_ip() {
    doctl compute load-balancer list -o json | \
        jq -r ".[] | select(.name == \"${DOMAIN}\").ip"
}

create_firewall() {
    echo -e "\nCreating firewall.\n"

    # Allow anything from our VPC and all droplet to droplet traffic
    # even if it comes from a public interface
    iprange=$(get_vpc_ip_range)
    inboundrules="protocol:icmp,address:$iprange,tag:$ALL_DROPLETS_TAG "
    inboundrules+="protocol:tcp,ports:all,address:$iprange,tag:$ALL_DROPLETS_TAG "
    inboundrules+="protocol:udp,ports:all,address:$iprange,tag:$ALL_DROPLETS_TAG "
    # Allow tcp 22 80 443 6443 22623 from the public
    for port in 22 80 443 6443 22623; do
        inboundrules+="protocol:tcp,ports:${port},address:0.0.0.0/0,address:::/0 "
    done
    inboundrules="${inboundrules:0:-1}" # pull off trailing space

    # Allow all outbound traffic
    outboundrules='protocol:icmp,address:0.0.0.0/0,address:::/0 '
    outboundrules+='protocol:tcp,ports:all,address:0.0.0.0/0,address:::/0 '
    outboundrules+='protocol:udp,ports:all,address:0.0.0.0/0,address:::/0'

    doctl compute firewall create           \
        --name $DOMAIN                      \
        --tag-names $ALL_DROPLETS_TAG       \
        --outbound-rules "${outboundrules}" \
        --inbound-rules "${inboundrules}" >/dev/null
}

get_firewall_id() {
    doctl compute firewall list -o json | \
        jq -r ".[] | select(.name == \"${DOMAIN}\").id"
}

create_vpc() {
    echo -e "\nCreating VPC for private traffic.\n"
    doctl vpcs create --name $DOMAIN --region $DIGITAL_OCEAN_REGION >/dev/null
}

get_vpc_id() {
    doctl vpcs list -o json | \
        jq -r ".[] | select(.name == \"${DOMAIN}\").id"
}

get_vpc_ip_range() {
    doctl vpcs list -o json | \
        jq -r ".[] | select(.name == \"${DOMAIN}\").ip_range"
}

create_domain_and_dns_records() {
    echo -e "\nCreating domain and DNS records.\n"
    # Create a domain in DO
    doctl compute domain create $DOMAIN >/dev/null

    # Set up some DNS records to point at our load balancer IP
    #
    # - Required for OpenShift
    #    -  oauth-openshift.apps.${DOMAIN}.
    #    -                *.apps.${DOMAIN}.
    #    -               api-int.${DOMAIN}.
    #    -                   api.${DOMAIN}.
    #
    ip=$(get_load_balancer_ip)
    for record in "api.${DOMAIN}."     \
                  "api-int.${DOMAIN}." \
                  "*.apps.${DOMAIN}."  \
                  "oauth-openshift.apps.${DOMAIN}.";
    do
        doctl compute domain records create $DOMAIN \
            --record-name $record \
            --record-type A       \
            --record-ttl 1800     \
            --record-data $ip >/dev/null
    done

    # Also enter in required internal cluster IP SRV records:
    #    _service._proto.name.              TTL  class  SRV # priority weight  port    target.
    # -------------------------------------------------------------------------------------------------
    #   _etcd-server-ssl._tcp.${DOMAIN}.  86400   IN    SRV     0        10    2380    etcd-0.${DOMAIN}
    #   _etcd-server-ssl._tcp.${DOMAIN}.  86400   IN    SRV     0        10    2380    etcd-1.${DOMAIN}
    #   _etcd-server-ssl._tcp.${DOMAIN}.  86400   IN    SRV     0        10    2380    etcd-2.${DOMAIN}
    for num in $(control_plane_num_sequence); do
        doctl compute domain records create $DOMAIN  \
            --record-name "_etcd-server-ssl._tcp.${DOMAIN}." \
            --record-type SRV      \
            --record-ttl 1800      \
            --record-priority 0    \
            --record-weight 10     \
            --record-port 2380     \
            --record-data "etcd-${num}.${DOMAIN}." >/dev/null
    done

    # Droplets should be up already. Set up DNS entries.

    # First for the control plane nodes:
    # Set up DNS etcd-{0,1,2..} records (required)
    # Set up DNS okd-control-{0,1,2..} records (optional/convenience)
    for num in $(control_plane_num_sequence); do
        id=$(doctl compute droplet list -o json | jq -r ".[] | select(.name == \"okd-control-${num}\").id")
        # Set DNS record with private IP
        ip=$(doctl compute droplet get $id -o json | jq -r '.[].networks.v4[] | select(.type == "private").ip_address')
        doctl compute domain records create $DOMAIN \
            --record-name "etcd-${num}.${DOMAIN}." \
            --record-type A       \
            --record-ttl 1800     \
            --record-data $ip >/dev/null
        # Set DNS record with public IP
        ip=$(doctl compute droplet get $id -o json | jq -r '.[].networks.v4[] | select(.type == "public").ip_address')
        doctl compute domain records create $DOMAIN \
            --record-name "okd-control-${num}.${DOMAIN}." \
            --record-type A       \
            --record-ttl 1800     \
            --record-data $ip >/dev/null
    done

    # Next, for the worker nodes:
    # Set up DNS okd-worker-{0,1,2..} records (optional/convenience)
    # Create worker nodes
    if have_workers; then
        for num in $(worker_num_sequence); do
            id=$(doctl compute droplet list -o json | jq -r ".[] | select(.name == \"okd-worker-${num}\").id")
            # Set DNS record with public IP
            ip=$(doctl compute droplet get $id -o json | jq -r '.[].networks.v4[] | select(.type == "public").ip_address')
            doctl compute domain records create $DOMAIN \
                --record-name "okd-worker-${num}.${DOMAIN}." \
                --record-type A       \
                --record-ttl 1800     \
                --record-data $ip >/dev/null
        done
    fi
}

# https://github.com/digitalocean/csi-digitalocean
configure_DO_block_storage_driver() {
    echo -e "\nCreating DigitalOcean block storage driver.\n"
    # Create the secret that contains the DigitalOcean creds for volume creation
    oc create -f - >/dev/null <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: digitalocean
  namespace: kube-system
stringData:
  access-token: "${DIGITALOCEAN_ACCESS_TOKEN}"
EOF

    # Deploy DO CSI storage provisioner
    DOCSIVERSION='2.0.0'
    oc apply -fhttps://raw.githubusercontent.com/digitalocean/csi-digitalocean/master/deploy/kubernetes/releases/csi-digitalocean-v${DOCSIVERSION}/{crds.yaml,driver.yaml,snapshot-controller.yaml} >/dev/null

    # Patch the statefulset for hostNetwork access so it will work in OKD
    # https://github.com/digitalocean/csi-digitalocean/issues/328
    PATCH='
    spec:
      template:
        spec:
          hostNetwork: true'
    oc patch statefulset/csi-do-controller -n kube-system --type merge -p "$PATCH" >/dev/null
}

fixup_registry_storage() {
    echo -e "\nFixing the registry storage to use DigitalOcean volume.\n"
    # Set the registry to be managed.
    # Will cause it to try and create a PVC.
    PATCH='
    spec:
      managementState: Managed
      storage:
        pvc:
          claim:'
    oc patch configs.imageregistry.operator.openshift.io cluster --type merge -p "$PATCH" >/dev/null

    # Update the image-registry deployment to not have a rolling update strategy
    # because it won't work with a RWO backing device.
    # https://kubernetes.io/docs/tasks/manage-kubernetes-objects/update-api-object-kubectl-patch/#use-strategic-merge-patch-to-update-a-deployment-using-the-retainkeys-strategy
    PATCH='
    spec:
      strategy:
        $retainKeys:
          - type
        type: Recreate'
    sleep 10 # wait a bit for image-registry deployment
    oc patch deployment image-registry -n openshift-image-registry -p "$PATCH" >/dev/null

    # scale the deployment down to 1 desired pod since the volume for
    # the registry can only be attached to one node at a time
    oc scale --replicas=1 deployment/image-registry -n openshift-image-registry >/dev/null

    # Replace the PVC with a RWO one (DO volumes only support RWO)
    oc delete pvc/image-registry-storage -n openshift-image-registry >/dev/null
    oc create -f - >/dev/null <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: image-registry-storage
  namespace: openshift-image-registry
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: ${REGISTRY_VOLUME_SIZE}Gi
  storageClassName: do-block-storage
EOF
}

destruct() {
    cat <<EOF
#########################################################
Deleting resources created for OKD. This is a dumb delete
which attempts to delete things without checking if they
exist so you'll need to ignore error messages if some
resources are already deleted.
#########################################################
EOF
    set +e
    echo -e "\nDeleting Load Balancer."
    lbid=$(get_load_balancer_id)
    doctl compute load-balancer delete $lbid --force
    echo -e "\nDeleting Firewall."
    fwid=$(get_firewall_id)
    doctl compute firewall delete $fwid --force
    echo -e "\nDeleting Domain and DNS entries."
    doctl compute domain delete $DOMAIN --force
    echo -e "\nDeleting Droplets."
    doctl compute droplet delete --tag-name $ALL_DROPLETS_TAG --force
    echo -e "\nDeleting Spaces (S3) bucket and all contents."
    aws --endpoint-url $SPACES_ENDPOINT s3 rb $SPACES_BUCKET --force
    sleep 20 # Allow droplets to get removed from the VPC
    echo -e "\nDeleting VPC."
    doctl vpcs delete $(get_vpc_id) --force
    echo -e "\nYOU WILL NEED TO MANUALLY DELETE ANY CREATED VOLUMES OR IMAGES"
    set -e
}

which() {
    (alias; declare -f) | /usr/bin/which --read-alias --read-functions --show-tilde --show-dot $@
}

check_requirement() {
    req=$1
    if ! which $req &>/dev/null; then
        echo "No $req. Can't continue" 1>&2
        return 1
    fi
}

main() {
    # If we want to destruct it all, then do that
    if [ "${1-}" == "destruct" ]; then
        destruct
        return 0
    fi

    # Check for required credentials
    for v in AWS_ACCESS_KEY_ID      \
             AWS_SECRET_ACCESS_KEY  \
             DIGITALOCEAN_ACCESS_TOKEN; do
        if [[ -z "${!v-}" ]]; then
            echo "You must set environment variable $v" >&2
            return 1
        fi
    done

    # Check for required software
    reqs=(
        aws
        doctl
        kubectl
        oc
        openshift-install
        jq
    )
    for req in ${reqs[@]}; do
        check_requirement $req
    done

    # Create the spaces bucket to hold the bulky bootstrap config
    # Doing it here tests early that the spaces access works before
    # we create other resources.
    aws --endpoint-url $SPACES_ENDPOINT s3 mb $SPACES_BUCKET >/dev/null

    # Create the image, load balancer, firewall, and VPC
    create_image_if_not_exists
    create_vpc; sleep 20
    create_load_balancer; sleep 20
    create_firewall

    # Generate the ignition configs (places bootstrap config in spaces)
    generate_manifests

    # Create the droplets and wait some time for them to get assigned
    # addresses so that we can create dns records using those addresses
    create_droplets; sleep 20
    # Print IP information to the screen for the logs (informational)
    doctl compute droplet list | colrm 63

    # Create domain and dns records. Do it after droplet creation
    # because some entries are for dynamic addresses
    create_domain_and_dns_records


    # Wait for the bootstrap to complete
    echo -e "\nWaiting for bootstrap to complete.\n"
    openshift-install --dir=generated-files  wait-for bootstrap-complete

    # remove bootstrap node and config space as bootstrap is complete
    echo -e "\nRemoving bootstrap resources.\n"
    doctl compute droplet delete bootstrap --force >/dev/null
    aws --endpoint-url $SPACES_ENDPOINT s3 rb $SPACES_BUCKET --force >/dev/null

    # Wait for the install to complete
    echo -e "\nWaiting for install to complete.\n"
    openshift-install --dir=generated-files  wait-for install-complete

    # Set the KUBECONFIG so subsequent oc or kubectl commands can run
    export KUBECONFIG=${PWD}/generated-files/auth/kubeconfig

    # Configure DO block storage driver
    # NOTE: this will store your API token in your cluster
    configure_DO_block_storage_driver

    # Configure the registry to use a separate volume created
    # by the DO block storage driver
    fixup_registry_storage
}

main $@
if [ $? -ne 0 ]; then
    exit 1
else
    exit 0
fi
