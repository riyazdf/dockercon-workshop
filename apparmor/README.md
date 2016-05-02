# dockercon-workshop
#### Dockercon 2016 Security Workshop

_Note: this exercise requires a host with AppArmor capability, such as Ubuntu 16.04_

AppArmor is a Linux Security Module (LSM) that protects an operating system by applying profiles to applications.
In contrast to managing capabilities with `CAP_DROP` and syscalls with Seccomp, AppArmor allows for much finer-grained
security profile control -- for example, AppArmor can restrict file operations on specified paths.


By default, Docker runs containers with the `docker-default` AppArmor profile, which is described in the [documentation here](https://docs.docker.com/engine/security/apparmor/#understand-the-policies).  Here are some quick pointers for how to understand AppArmor profiles:
  
  - The include statements (such `#include <abstractions/base>`) behave just like their C-looking counterparts,
  by expanding to additional AppArmor profile contents

  - AppArmor is a deny-first system, specified by the `deny` clause.  Once a path or other resource is denied, it is impossible
  to regain access to it with an `owner` statement in the same profile

  - For file operations, `r` corresponds to read, `w` to write, `k` to lock, `l` to link, and `x` to execute

 This should get you started fairly well with AppArmor, but for more information you can consult the official [AppArmor documentation wiki](http://wiki.apparmor.net/index.php/Documentation) (under active development at this time).

## Default AppArmor in Docker

1.  We can view the status of AppArmor on our Docker host by running `apparmor_status` (may require admin credentials) -- you should notice the `docker-default` profile is in enforce mode.  As described above, this is Docker's default AppArmor profile that is applied to containers on `docker run`.

2.  To prove that this profile is applied by default, run an alpine container in another terminal `docker run --rm -it alpine sh` and then check `apparmor_status` again.  You should now see that a process (our alpine container!) has a profile defined and is also in enforce mode:
    ```
    1 processes have profiles defined.
    1 processes are in enforce mode.
       docker-default (28462)
    ```

    Enforce mode will actively deny various operations due to the AppArmor profile; complain mode will only log profile violations but not block any functionality.

3.  Now kill that container and start another alpine container, but this time without an AppArmor profile.  In order to disable AppArmor, we must pass an additional flag to Docker: `docker run --rm -it --security-opt apparmor=unconfined alpine sh`.  Check `apparmor_status` in another terminal to confirm that this container is not running with a profile.

4.  Let's understand the default AppArmor profile, and the defense-in-depth of the Docker engine profiles.  AppArmor works together with Seccomp and a capabilities whitelist to provide security by default:
	- Disable seccomp and add the `SYS_ADMIN` capability while running an Ubuntu container: `docker run --rm -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu sh`

	- Make two directories and run mount to bind them: `mkdir 1; mkdir 2; mount --bind 1 2` -- you should receive a permissions error because the `docker-default` AppArmor profile will deny mount!

	- To convince yourself this is the case, run the same commands with AppArmor also disabled: `docker run --rm -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu sh`


## Our Custom AppArmor Profile

The Panama Papers hack exposed millions of documents from Mossack Fonseca, a Panamanian law firm.  A probable cause, as described by [Wordfence](https://www.wordfence.com/blog/2016/04/mossack-fonseca-breach-vulnerable-slider-revolution/) and other reports was an unpatched Wordpress plugin -- in particular, the Revolution Slider plugin contained buggy code that allowed a new plugin to take its place by making an [unauthenticated AJAX call to the plugin](https://www.wordfence.com/wp-content/uploads/2016/04/Screen-Shot-2016-04-07-at-10.31.37-AM.png).


Since Wordpress and its plugins run as PHP, an attacker could upload their own malicious plugin to start a shell on Wordpress, and simply send a request to the PHP resource to run the malicious code to spin up the shell.


We'll show how a custom AppArmor profile could have protected Wordpress from this attack vector, in a Docker container.


1.  Check out the `apparmor` branch and traverse to the wordpress directory: `cd wordpress`

2.  Open the docker-compose file (`docker-compose.yml`) -- you'll notice we define Wordpress with two containers - a wordpress container that wraps Apache PHP, and a database to store data.  Build and spin up wordpress with the `docker-compose build` and `docker-compose up` commands.

3.  After bringing up wordpress with `docker-compose up`, visit your local instance of wordpress at `https://<PUBLIC_IP>:8080` and set up an account.  After you've logged in, notice how you can add any plugin without any restriction through the Plugins tab on the webpage; the `docker-default` AppArmor profile does not restrict any wordpress filepath writes.

4.  As is, this wordpress container is vulnerable to the Revolution Slider "update plugin" attack.  Try adding a plugin from the wordpress UI and watch as it succeeds.
However, note that an attacker would not be able to easily pivot to view underlying files on the host since our wordpress setup is in a container.  To convince yourself this is the case, `docker exec` into the wordpress container and attempt to access your hosts's filesystem.

5.  Even though the wordpress container is isolated from our host, we'd like to prevent any malicious plugins or themes from being uploaded to our wordpress instance.  As a first step, let's add the `wparmor` AppArmor profile to our `docker-compose.yml` file.  The syntax is similar to the `docker run --security-opt` format: you'll need an outer `security-opt` key with a nested `apparmor=wparmor` key.

6.  If you tried to `docker-compose up` after the last step, you probably received a failure because you hadn't parsed the AppArmor profile yet: to do so, run `sudo apparmor_parse wparmor`.  There's still work to be done on this AppArmor profile, as it does not block uploads.

7.  Edit the `wparmor` profile to deny every directory under `/var/www/html` except for the `uploads` directory (which is used for media).  Note that `*` wildcard is only for files at a single level, whereas `**` will traverse to subdirectories.  Also as we described earlier, if a path is denied by an AppArmor profile statement, an `owner` statement cannot overwrite it -- you should add 3 lines to the `wparmor` file in this step, two `deny` and one `owner` for `/var/www/html/wp-content/plugins/`, `/var/www/html/wp-content/themes/`, and `/var/www/html/wp-content/uploads/`

8.  Parse the `wparmor` again and bring back up your docker-compose wordpress instance.  Test that your AppArmor profile is correct by successfully uploading an image to the site via the wordpress UI, but not being able to upload a plugin to wordpress.  Note that if the usual upload flow for a plugin fails, wordpress will point you to a FTP upload page.  Also test that you're still able to upload a photo from the media tab.

If you've completed the last step successfully, congratulations!  You've secured a wordpress instance against adding malicious plugins :)


## Extra for Experts

AppArmor profiles are quite application-specific -- while we've had some practice at writing our own profiles by hand, wouldn't it be nice to have some tools for debugging and generating AppArmor profiles?  We'll explore `aa-complain` and `aa-genprof` to help us achieve these goals.

1.  On Ubuntu, start by installing `apparmor-utils`:

    `sudo apt install apparmor-utils`

    `apparmor-utils` will install our two tools, as well as other helpful tools.  For more information about this package, read [Ubuntu's guide](https://help.ubuntu.com/lts/serverguide/apparmor.html).


2.  Let's use these tools with the Firefox app. Let's start with automatically generating AppArmor profiles with `aa-genprof`:

	`sudo aa-genprof firefox`

	You should see your terminal go into an interactive mode -- this is AppArmor watching the Firefox app.  Go ahead and open the Firefox app and browse some websites, maybe download some content, and generally exercise usual web-browsing behavior.  If you go back to the terminal running `aa-genprof`, you can press `s` to view events from the system log and decide whether or not to include these events in your AppArmor profile as an allow or deny statement.  When you're done, press `f` to finish -- you can view your profile in `/etc/apparmor.d/usr.bin.firefox` on an Ubuntu machine.

	You can also use `aa-autodep` to automatically generate profiles, but this command will create an even more minimal profile.

	To further refine an existing profile, `aa-logprof` operates in the same manner as `aa-genprof` but for amending a profile by scanning logs.


3.  Debug AppArmor profiles with `aa-complain`: as described earlier, AppArmor has a "complain" mode of operation that does not actively block any violations to its security profile, but will instead log these events.  This is a fantastic tool for debugging, let's try viewing our Firefox profile:

    `sudo aa-complain /etc/apparmor.d/usr.bin.firefox`

    You can confirm that this set the Firefox policy to complain mode by running `apparmor_status`.  To view any complaints from apparmor, run `dmesg`.