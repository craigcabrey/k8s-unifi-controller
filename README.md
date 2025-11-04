# k8s-unifi-controller

A simple controller to keep firewall rules to up date.

## Prerequisites

* Unifi Dream Machine (and likely SE)
  * Support could be added for the standalone network controller if needed
* Functioning network (e.g. this will not magically fix network issues if manual port forwards aren't working)

## Deploying

There are example manifests under `manifests/` which should be all you need to get started. The container image is available at `ghcr.io/craigcabrey/unifi-controller`.

## Using

Once deployed, the controller will watch for services labeled with `io.github.craigcabrey/unifi-forward-ports` (which can be overridden via the `--label` flag). The value of the label should be `true` OR the ID of a firewall group used for tracking IPv6 addresses. For example:

```
$ k get svc ingress-controller -o yaml
apiVersion: v1
kind: Service
metadata:
  labels:
<snip>
    io.github.craigcabrey/unifi-forward-ports: 64ec19326868ee84586bb608
<snip>
```

If set to a firewall group ID, the controller will sync the contents of the firewall group with the IPv6 addresses of the service. Then, you can add a firewall group that references the firewall group in the Unifi controller. If the IPv6 address of the service changes (which *can* happen), the firewall will be seamlessly updated.

## Developing

It's strongly recommended to use `virtualenv` or `venv`. Once you have a environment setup, run `scripts/setup.sh`.

There is a builting dry run mode which makes development much nicer. If you intend on submitting a pull request, please make sure to maintain the integrity of the dry run functionality. Likewise for code styling. There is a helper `prep.sh` for style & type checking.

## Limitations

This controller assumes _full_ control over port forwarding rules. It does not validate for manually added rules. It uses rule names to match against existing rules. Do not edit port forwarding rules manually if you intend to use this system.

Likewise, the controller does not currently validate for duplicate port rules. A future version may add this functionality, but for now it is your responsibility to guarantee port uniqueness.

This system uses an unofficial API of the Unifi network application. It may change behavior on any update and break your system. I am not responsible for any breakages.

If you _do_ end up in a state with invalid rules, it _should_ be relatively easy to remove rules directly via the MongoDB client. Note that this is still an advanced procedure and may cause unintended consequences or behavior.
