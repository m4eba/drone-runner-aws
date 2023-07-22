Sample pool file for hetznercloud:

```yml
version: "1"
instances:
- name: hetzner-pool
  type: hetznercloud
  pool: 1    # total number of warm instances in the pool at all times
  limit: 5   # limit the total number of running servers. If exceeded block or error.
  platform:
    os: linux
    arch: amd64
  spec:
      account:
        token: XXXXXXXXXXXXXXXXXXXXX
        region: fsn1
      image: ubuntu-22.04
      size: cx21
```
