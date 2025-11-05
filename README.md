# k8s-unifi-controller

A simple controller to keep firewall rules to up date.

## Prerequisites

* Unifi Dream Machine (and likely SE)
  * Support could be added for the standalone network controller if needed
* Functioning network (e.g. this will not magically fix network issues if manual port forwards aren't working)

## Deploying

There are example manifests under `manifests/` which should be all you need to get started. The container image is available at `ghcr.io/craigcabrey/unifi-controller`.

## Using

Once deployed, the controller will watch for services labeled with either `io.github.craigcabrey/unifi-forward-ports` (which can be overridden via the `--label` flag) or `io.github.craigcabrey/unifi-firewall-group` (`--firewall-group-label`). The former will publish port forward rules for IPv4 services, while the latter will publish firewall groups for IPv6 services.

```
$ k get svc ingress-controller -o yaml
apiVersion: v1
kind: Service
metadata:
  labels:
<snip>
    io.github.craigcabrey/unifi-forward-ports: true
    io.github.craigcabrey/unifi-firewall-group: true
<snip>
```

Rules will be created with deterministic names. Then, you can add a firewall group that references the firewall group in the Unifi controller. If the IPv6 address of the service changes (which *can* happen), the firewall will be seamlessly updated.

**Note! This controller is ended to control ALL port forwards & firewall groups. It WILL delete other rules!**

## Developing

There is a builting dry run mode which makes development much nicer. If you intend on submitting a pull request, please make sure to maintain the integrity of the dry run functionality. Likewise for code styling.

## Limitations

This controller assumes _full_ control over rules. It does not validate for manually added rules. It uses rule names to match against existing rules. Do not edit port forwarding rules manually if you intend to use this system.

Likewise, the controller does not currently validate for duplicate port rules. A future version may add this functionality, but for now it is your responsibility to guarantee port uniqueness.

This system uses an unofficial API of the Unifi network application. It may change behavior on any update and break your system. I am not responsible for any breakages.

If you _do_ end up in a state with invalid rules, it _should_ be relatively easy to remove rules directly via the MongoDB client. Note that this is still an advanced procedure and may cause unintended consequences or behavior.
