Green Screens Linux Installer - Preflight
=========================================

Copyright 2016., Green Screens Ltd. <info@greenscreens.io>

This are Bash and Docker scripts to install and update **Green Screens Terminal Service** in Linux Docker environment.

Scripts are in preflight mode intended for testing Linux environment. Only difference to production script
is link to sample deployment module for testing installation procedure.

# Install instructions

1. Enable Limit Memory and CPU for Docker Containers

   Open grub file

   `sudo vi /etc/default/grub`

   Change this variable

   `GRUB_CMDLINE_LINUX="cgroup_enable=memory swapaccount=1"`

   Update changes

   `sudo update-grub`

2. Install product

   Download install script and start install

   `sudo curl -fsSL https://raw.githubusercontent.com/greenscreens-io/linux-docker/master/install.sh | sh`

   or this to map different ports between host and docker

   `sudo curl -fsSL https://raw.githubusercontent.com/greenscreens-io/linux-docker/master/install.sh | sh -s -- -p 80 -s 443`

   Install simple preconfigured NginX (optional)

   `sudo bash gsinstall.sh -n`

   Show help

   `sudo bash gsinstall.sh -h`

   By default, ports 8080, 8443 and 8843 will be mapped between host and docker container.
   To remap, NginX service can be used as an alternative approach.

   For more advanced NginX setup, visit our GitHub repository
   https://github.com/greenscreens-io/nginx_config

3. Update to new version (no need to run after initial install)

   Call script with update flag

   `sudo bash gsinstall.sh -u`

   or with port remapping
   
   `sudo bash gsinstall.sh -p 80 -s 443 -u`


# Copyright

    Copyright 2016. Green Screens Ltd. All rights reserved.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
    