#!/bin/bash

# (c) Copyright 2016, Green Screens Ltd.

sudo curl -Lo gsinstall.sh https://raw.githubusercontent.com/greenscreens-io/linux-docker/master/greenscreens-install.sh \
	&& sudo chmod 777 gsinstall.sh \
	&& sudo bash gsinstall.sh
