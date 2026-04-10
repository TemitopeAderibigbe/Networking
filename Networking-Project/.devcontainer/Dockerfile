FROM gtinfosec/network-v2


# Uncomment and re-build the devcontainer if running John results in an "Illegal instruction" error
# USER root
#
# RUN cd /usr/share/john/src && \
# 	./configure CFLAGS='-DJOHN_SYSTEMWIDE -DJOHN_SYSTEMWIDE_EXEC="\"/usr/share/john/run/john\"" -DJOHN_SYSTEMWIDE_HOME="\"/usr/share/john/run\""' && \
# 	make -s clean && make -sj$(nproc)
#
# USER cs3235

# If you need to do any additional setup for development
# in the container like installing additional programs,
# do it in this file so that the changes are persisted.
#
# NOTE: you should *NOT* be installing additional Go modules
# here; everything available to you in grading is already installed.
# Installing additional modules may cause your code to become ungradeable.
#
# Example: to install Emacs, we might add:
#    RUN sudo apt-get update && sudo apt-get install -y emacs
