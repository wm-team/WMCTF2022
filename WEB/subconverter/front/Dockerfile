FROM ubuntu:20.04
COPY ./files /tmp/files
RUN export DEBIAN_FRONTEND=noninteractive && \
sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.aliyun.com/g" /etc/apt/sources.list && \
sed -i "s/http:\/\/security.ubuntu.com/http:\/\/mirrors.aliyun.com/g" /etc/apt/sources.list && \
apt-get update && \
apt-get upgrade -y && \
apt-get install -y python3 python3-pip && \
pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple flask requests && \
mv /tmp/files/start.sh /start.sh && \
mkdir /app && \
mv /tmp/files/app.py /app/app.py && \
chmod 755 /start.sh && \
rm -rf /tmp/files && \
echo done
CMD ["/start.sh"]