# dockercon-workshop
#### Dockercon 2016 Security Workshop

### cgroups

cgroups, short for "control groups"
TODO(riyazdf): writeup on cgroups, using from docker cli and docker-compose

- cpu set demo with stress tool
- fork bomb demo


`docker run --rm -it --pids-limit 200 debian:jessie bash`
`:(){ :|: & };:`
