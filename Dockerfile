FROM ubuntu:19.04
RUN apt update 
RUN apt install -y --allow-downgrades libgnutls30=3.6.5-2ubuntu1 libsystemd0=240-6ubuntu5
RUN apt install -y libmicrohttpd-dev libjansson-dev libcurl4-gnutls-dev libgnutls28-dev libgcrypt20-dev libsystemd-dev wget libncurses5 libelf1 unzip rpm2cpio cpio gnutls-bin && \
    wget https://github.com/babelouest/ulfius/releases/download/v2.6.3/ulfius-dev-full_2.6.3_ubuntu_disco_x86_64.tar.gz && \
    tar xzvf ulfius-dev-full_2.6.3_ubuntu_disco_x86_64.tar.gz && \
    dpkg -i liborcania-dev_2.0.1_ubuntu_disco_x86_64.deb && \
    dpkg -i libyder-dev_1.4.7_ubuntu_disco_x86_64.deb && \
    dpkg -i libulfius-dev_2.6.3_ubuntu_disco_x86_64.deb && \
    rm ulfius-dev-full_2.6.3_ubuntu_disco_x86_64.tar.gz && \
    rm liborcania-dev_2.0.1_ubuntu_disco_x86_64.deb && \
    rm libyder-dev_1.4.7_ubuntu_disco_x86_64.deb && \
    rm libulfius-dev_2.6.3_ubuntu_disco_x86_64.deb
COPY ["./RHELinux x64-Rls-v10.10.zip", "/"]
RUN mkdir CPInstall && \
    mkdir /etc/opt/CARKaim && \
    mkdir /etc/opt/CARKaim/vault && \
    mkdir /etc/opt/CARKaim/conf
RUN ["unzip", "-j", "/RHELinux x64-Rls-v10.10.zip", "-d", "CPInstall"]
RUN ["rm", "/RHELinux x64-Rls-v10.10.zip"]
RUN rpm2cpio CPInstall/CARKaim-10.10.00.60.x86_64.rpm | cpio -idv --extract-over-symlinks && \
    cp /opt/CARKaim/sdk/libcpasswordsdk.so /usr/lib/ && \
    mkdir /var/lock/subsys && \
    mkdir /opt/CARKaim/LinuxCCP && \
    rm -rf /CPInstall
COPY ./LinuxCCP /opt/CARKaim/LinuxCCP/LinuxCCP
COPY ./startservice.sh /startservice.sh

ENTRYPOINT ["/startservice.sh"]

