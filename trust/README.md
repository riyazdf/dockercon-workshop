# dockercon-workshop
#### Dockercon 2016 Security Workshop

## Distribution and Trust Exercise

This exercise focuses on understanding and securing image distribution -- we'll
start with a simple `docker pull` and build up to using Docker Content Trust.

### Docker pull by tag

When pulling with docker, you're probably most familiar with pulling by tag.
Pulls by tag are demarcated by specifying a alphanumeric, human-chosen tag for
an image, for example:

`docker pull library/alpine:edge`

In this pull command, we're pulling the alpine image tagged as `edge` from the library repository.
The command specified the `edge` tag, but had we not specified a tag (ex:
`docker pull library/alpine`), docker defaults to trying to pull the `latest`
tag.

The corresponding image on hub can be found at
`https://hub.docker.com/r/_/alpine/`.

1.  Go ahead and try running the command above: `docker pull
    library/alpine:edge` -- what do you see in the output?

2.  Once you've pulled alpine edge, confirm the pull was successful by running
    `sh` in the container in interactive mode: `docker run --rm -it alpine:edge
    sh`. You should be able to run `ls` in the shell and see similar output:
```
/ # ls
bin      dev      etc      home     lib      linuxrc  media    mnt      proc
root     run      sbin     srv      sys      tmp      usr      var
```

### Docker pull by digest

During the last pull by tag exercise, you might have noticed that `docker pull
library/alpine:edge` produced a line that looked like `Digest:
sha256:b7233dafbed64e3738630b69382a8b231726aa1014ccaabc1947c5308a8910a7`.

Note that pulling the same image by tag may pull a different digest -- in fact,
when you're doing this exercise you may have noticed that you pulled down a
different digest for `alpine:edge`!  This is because you can repush the same tag
with different image contents.

While mutable tags might be a good thing for distributing security updates, it
may also lead to unexpected bugs or security vulnerabilities in your application
if the tag points to different images from what your production environments expect.

This is why pulling by digest is a powerful docker operation - since docker uses
a content-addressable store for images, we can pin our pulls to specific image
contents by pulling the digest directly.  We'll pull by digest in the example
below:

1.  Run the command `docker pull
    alpine@sha256:b7233dafbed64e3738630b69382a8b231726aa1014ccaabc1947c5308a8910a7`
    and check that the pull succeeded by running that image.

2.  Run the command `docker images --digests alpine` and inspect the output.  In
    particular, note that there are now two alpine images that correspond to
    the edge tag we pulled - one will list the `edge` tag itself and the other
    will contain a `<none>` tag along with the `b7233daf...` digest.

For more information about `docker pull` in general, please reference
[these docs](https://docs.docker.com/engine/reference/commandline/pull/).

### Docker Content Trust

It's not easy to find the digest that corresponds to a particular image tag,
since it is computed from the hash of the image contents itself and stored in the
image manifest which is stored in the registry.  This is why we needed a `docker pull`
by tag to find digests previously.  Moreover, it would be desirable to have additional
security guarantees for pulling images so we don't have to trust the registry, such as
freshness.

Enter Docker Content Trust: a system currently in the Docker engine that verifies the
publisher of images without sacrificing usability.  Docker Content Trust implements
[The Update Framework](https://theupdateframework.github.io/) (TUF), a NSF-funded research
project succeeding Thandy of the Tor project -- TUF uses a key hierarchy to ensure recoverable
key compromise and robust freshness guarantees.

Under the hood, Docker Content Trust handles name resolution from docker tags to digests by
signing its own metadata -- when Content Trust is enabled, docker will verify the signatures
(and expiration dates) in this metadata before rewriting a pull by tag command to a pull by digest.

1.  Enable Docker Content Trust by setting the environment variable:
    `export DOCKER_CONTENT_TRUST=1`

2.  Even though Docker Content Trust is enabled, all docker commands remain unchanged!
    Try pulling down a signed image tag: `docker pull riyaz/dockercon:trust`
    Take particular notice at the name translation, how the command is translated to:
    `Pull (1 of 1): riyaz/dockercon:trust@sha256:88a7163227a54bf0343aae9e7a4404fdcdcfef8cc777daf9686714f4376ede46`

3.  Now try pulling an unsigned image, still with Docker Content Trust enabled:
	`docker pull riyaz/dockercon:untrusted`.  Notice we receive an informative error
	explaining that no trust data is available.

4.  Push your own image with Content Trust!  First tag an image, then push:
	`docker tag alpine <INSERT_HUB_USERNAME>/alpinetrust:trusted`

	
	`docker push <INSERT_HUB_USERNAME>/alpinetrust:trusted`

	
	On this command, you'll notice that you are prompted for passphrases -- this is because
	Docker Content Trust is generating a hierarchy of keys with different signing roles.
	Each key is encrypted with a passphrase, and as such a best practice is to provide different
	passphrases for each key.
	
	
	Of note, the root key is the most important key in TUF, as it can rotate any other key in the system.
	The root key should be kept offline as much as possible, or in hardware.
	It is stored in `~/.docker/trust/private/root_keys` by default.
	
	
	The tagging key is the only local key required to push new tags to an existing repo,
	and is stored in `~/.docker/trust/private/tuf_keys` by default.
	
	
	We encourage you to explore your `~/.docker/trust` directory to view the internal metadata
	and key information that Docker Content Trust generates.

5.  Try pulling the image you just pushed with and without Content Trust enabled (alternate between
    `export DOCKER_CONTENT_TRUST=1` and `unset DOCKER_CONTENT_TRUST`).
    What different output do you see?	

For more information about Docker Content Trust, please reference
[these docs](https://docs.docker.com/engine/security/trust/).

### Official Images

All images in hub under the `library` organization (currently viewable at: https://hub.docker.com/explore/)
are deemed "Official Images."  These images undergo a rigorous, [open-source](https://github.com/docker-library/official-images/)
review process to ensure they follow best practices -- for example, having lean and clear Dockerfiles.

It is strongly encouraged to use official images whenever possible, as they are hand-curated and also signed!

In fact, the `library/alpine` image we pulled earlier is an official image, and can also be pulled as `alpine`

1.  With Docker Content Trust enabled, try pulling `alpine:edge` again.

2.  Pick your favorite official image from https://github.com/docker-library/official-images/ and pull it with Content Trust.

### Extra for Experts

Docker Content Trust is powered by [Notary](https://github.com/docker/notary), an open-source TUF-client server and client
that can operate over arbitrary trusted collections of data.  Notary has its own CLI with more robust features,
such as the ability to rotate keys and remove trust data.  In this section, we'll play with the Notary CLI and our own local instance of the Notary server instead of the one deployed alongside Docker Hub.

1.  Get a notary client: this can be done by downloading a binary directly from the [releases page](https://github.com/docker/notary/releases)
    or by cloning the notary repository into a valid Go repository structure (instructions at the end of the README)
    and building a client by running `make binaries`.  If you build the notary binary yourself, it will be placed in the `bin` subdirectory within the notary git repo directory.

2.  Use the notary client to inspect an existing Docker Hub repository:
	`$ notary -s https://notary.docker.io -d ~/.docker/trust list docker.io/library/alpine`
	Note that `docker.io/` must be prepended to the image name for hub images.  You should also try your own image you pushed to hub earlier!

3.  Clone the [Notary](https://github.com/docker/notary) repository if you haven't already, and bring up a local notary server and signer with compose: `docker-compose up` from inside the `notary` directory.

4.  Now point your notary client to your local notary server -- add `127.0.0.1 notary-server` to your `/etc/hosts`, or if using `docker-machine`, add `$(docker-machine ip) notary-server)`.  Also, run ` mkdir -p ~/.notary && cp cmd/notary/config.json cmd/notary/root-ca.crt ~/.notary` from the notary directory to copy the proper config and certificate to talk to your local server.

5.  Let's play with the notary client: initialize a new trusted collection on your local server `notary init example.com/scripts`
    Just like when we pushed a new repo for the first time with Docker Content Trust, you should be prompted for passphrases for root and repository keys.

6.  Add content to your trusted collection: run a sequence of `notary add example.com/scripts <NAME> <FILE>`, `notary publish example.com/scripts`, and `notary list example.com/scripts`.  In order, this sequence:
    - Stages adding a target with the `notary add` command
    - Attempts to publish this target to the server with `notary publish`
    - Fetches and displays all trust data for example.com, verifying output as it is downloaded

    To remove targets, you can make use of the `notary remove example.com/scripts <NAME>` command, followed by a `notary publish example.com/scripts`.

7. Let's make use of some notary client power-features -- starting with key rotation!  In the event of key-compromise, it's simple to rotate keys with notary: simply determine which key you wish to rotate, and run `notary key rotate`!  Here are the exact steps:
   - Determine which role you'd like to rotate the key for: we can view all of our local keys by running a `notary key list`.  In this example we'll rotate our `targets` key.  For more information about keys, please read this [notary documentation](https://docs.docker.com/notary/service_architecture/#brief-overview-of-tuf-keys-and-roles)
   - Run the key rotate command: `notary key rotate example.com/scripts targets`.  You should notice that notary will generate a new key and ask for a new passphrase to encrypt this key with
   - Run `notary key list` to confirm that the targets key ID has changed

8.  Now we'll explore delegation roles in notary.  Delegation roles are a subset of the targets role, and are perfect for administering signing privileges to collaborators and CI systems because no private key sharing is required.  Here's a [demo of setting up delegation roles](https://asciinema.org/a/4nclzcuus3ubdcu88xmepz8u4) to illustrate the steps below:
	- Rotate the snapshot key to the server -- this is done by default when creating new Content Trust repositories in Docker 1.10+: `notary key rotate example.com/scripts snapshot -r`.  This is so that delegation roles will only require their own delegation's private key to publish to trusted collections.

	- Have your delegate generate a x509 certificate + private key pair with openssl, [instructions here](https://docs.docker.com/engine/security/trust/trust_delegation/#generating-delegation-keys).  Retrieve their certificate, `delegation.crt`.

	- Add their delegation role: `notary delegation add example.com/scripts targets/releases delegation.crt --all-paths`

	  This command will allow the collaborator to push any target (from `--all-paths`) to the `targets/releases` role if they can sign with their private key `delegation.key` in order to produce a valid signature that can be verified by `delegation.crt`'s public key material.

	  Note that this commmand only stages the delegation role addition.

	- Publish the addition of the delegation role: `notary publish example.com/scripts`

	- Check that the delegation role was added: `notary delegation list example.com/scripts`

	- Now your collaborator should be able to publish content with a `docker push` with Docker Content Trust enabled, or with a `notary add example.com/scripts <NAME> <FILE> -r targets/releases`.  You can verify their pushes by running a `notary list example.com/scripts -r targets/releases`

	- You can add additional keys to the same role with additional `delegation add` commands, like so: `notary delegation add example.com/scripts targets/releases delegation2.crt delegation3.crt`, followed by a publish

	- For more commands over delegation roles, please consult the notary [advanced usage documentation](https://docs.docker.com/notary/advanced_usage/#work-with-delegation-roles).
