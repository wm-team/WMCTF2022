FROM ubuntu:20.04

# NOTES:
# subconverter:
# https://github.com/tindy2013/subconverter/actions/runs/2803016137
# it is the latest subconverter version v0.7.2-f9713b4
# pref.toml.orig: same as official pref.example.toml, only changed api_mode=true and api_access_token=(random generated every 5 minutes)
# readflag.c: execute /readflag to get flag.

COPY ./files /tmp/files
RUN export DEBIAN_FRONTEND=noninteractive && \
sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.aliyun.com/g" /etc/apt/sources.list && \
sed -i "s/http:\/\/security.ubuntu.com/http:\/\/mirrors.aliyun.com/g" /etc/apt/sources.list && \
apt-get update && \
apt-get upgrade -y && \
apt-get install -y curl wget gcc && \
gcc /tmp/files/readflag.c -o /readflag && \
mkdir /app && \
mv /tmp/files/subconverter /app/subconverter && \
mv /tmp/files/pref.toml.orig /app/pref.toml.orig && \
mv /tmp/files/start.sh /start.sh && \
mv /tmp/files/flag /flag && \
useradd ctf && \
chown ctf:ctf /app && \
chmod 700 /start.sh && \
chmod 755 /app/subconverter && \
chmod 744 /app/pref.toml.orig && \
chmod 755 /readflag && \
chmod u+s /readflag && \
chmod 700 /flag && \
rm -rf /tmp/files && \
echo done
CMD ["/start.sh"]