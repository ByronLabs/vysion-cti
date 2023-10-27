#!/bin/bash
ansible-playbook -u vysion --ask-pass -i ansible ansible/vysion-misp.yml -K -vvv
