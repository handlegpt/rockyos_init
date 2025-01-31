#!/bin/bash

# RabbitOps Initialization Script
# 定义退格键
stty erase ^H

############################################
# 1. SELinux 状态检查并禁用
############################################
if sestatus | grep -q 'enabled'; then
  echo "SELinux 当前状态: Enabled。正在禁用..."
  setenforce 0
  sed -i '/^SELINUX=/s/enforcing/disabled/' /etc/selinux/config
  echo "SELinux 已临时禁用，并配置为永久禁用。重启后生效。"
else
  echo "SELinux 当前状态: 已禁用。无需操作。"
fi

############################################
# 2. 清理旧包并安装常用软件
############################################
# Rocky Linux 9 默认使用 dnf
dnf remove -y mysql* java* httpd* php* subversion*
# 安装 EPEL 源，确保能安装一些在官方源中未提供的工具
dnf install -y epel-release
# 安装常用必备包
dnf install -y vim curl gcc gcc-c++ make cmake net-tools sysstat wget \
               crontabs pcre-devel zlib-devel bc chrony rsyslog logrotate \
               iptables-nft iptables-services screen htop iftop nmon fail2ban

# 更新系统
dnf -y update
# 清理并重建缓存
dnf clean all
dnf makecache

############################################
# 3. 下载并配置 tcping (可选)
############################################
if [ ! -f "/usr/bin/tcping" ]; then
  cd /usr/bin
  wget -O tcping https://soft.mengclaw.com/Bash/TCP-PING
  chmod +x tcping
fi

############################################
# 4. 获取本机外网 IP
############################################
IP2=$(curl --connect-timeout 10 -s whatismyip.akamai.com)
if [ -z "$IP2" ]; then
  echo "无法获取外网 IP，请手动检查网络连接。"
  IP2="0.0.0.0" # 默认占位
fi

############################################
# 5. 随机生成 SSH 端口号（1024-65535）
############################################
RANDOM_PORT=$((RANDOM % 64512 + 1024))
echo "随机生成的 SSH 端口为: $RANDOM_PORT"

############################################
# 6. 配置 iptables 规则，仅允许当前外网 IP 访问 SSH
############################################
# 如果你更倾向于使用 nftables，请根据 nftables 的写法进行修改
cat > /etc/sysconfig/iptables <<EOF
*filter
-F
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# 允许已建立和相关的连接
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 允许本地流量
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# 仅允许当前外网 IP 访问随机生成的 SSH 端口
-A INPUT -m conntrack --ctstate NEW -p tcp -s $IP2 --dport $RANDOM_PORT -j ACCEPT
-A INPUT -m conntrack --ctstate NEW -p tcp -s IP地址 --dport $RANDOM_PORT -j ACCEPT

# 限制 SSH 尝试速率
-A INPUT -p tcp --dport $RANDOM_PORT -m state --state NEW -m recent --set
-A INPUT -p tcp --dport $RANDOM_PORT -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP

# 允许 HTTP 和 HTTPS
-A INPUT -m conntrack --ctstate NEW -p tcp --dport 80 -j ACCEPT
-A INPUT -m conntrack --ctstate NEW -p tcp --dport 443 -j ACCEPT

# 限制 ICMP 请求速率
-A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/sec -j ACCEPT
-A INPUT -p icmp --icmp-type echo-request -j DROP

# 日志记录未被匹配的流量
-A INPUT -j LOG --log-prefix "DROP: " --log-level 4

COMMIT
EOF

# 保存并重启 iptables 服务
if [ -f "/usr/sbin/iptables-restore" ]; then
  iptables-restore < /etc/sysconfig/iptables
  systemctl enable iptables
  systemctl start iptables
  echo "外网 IP ($IP2) 已被配置为允许访问 SSH。"
else
  echo "未找到 iptables-restore 命令，请确认 iptables 是否正确安装。"
fi

############################################
# 7. 修改 root 和 monster 用户密码
############################################
SUBPASS=$(openssl rand -base64 16)
echo "root:$SUBPASS" | chpasswd

if ! id "monster" &>/dev/null; then
  useradd monster
  SUBPASS2=$(openssl rand -base64 16)
  echo "monster:$SUBPASS2" | chpasswd
else
  echo "用户 'monster' 已存在，跳过创建。"
fi

# 配置 monster 用户的 sudo 权限
cat > /etc/sudoers.d/monster << EOF
monster ALL=(ALL) NOPASSWD: ALL
monster ALL=(ALL) NOPASSWD: !/usr/bin/passwd,!/usr/sbin/visudo,!/usr/sbin/useradd,!/usr/sbin/userdel,!/usr/sbin/usermod,!/usr/bin/gcc,!/usr/bin/make,!/usr/bin/chattr,!/sbin/iptables
EOF

############################################
# 8. 修改 SSH 服务端口、禁用 root 远程登录
############################################
if grep -q "^#Port" /etc/ssh/sshd_config; then
  sed -i "s/^#Port .*/Port $RANDOM_PORT/" /etc/ssh/sshd_config
else
  # 若脚本多次运行，建议做更严谨的判断，这里简单示例
  echo "Port $RANDOM_PORT" >> /etc/ssh/sshd_config
fi

if grep -q "^#PermitRootLogin" /etc/ssh/sshd_config; then
  sed -i "s/^#PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
else
  echo "PermitRootLogin no" >> /etc/ssh/sshd_config
fi

systemctl restart sshd
if systemctl status sshd | grep -q "active (running)"; then
  echo "SSH 服务已重新启动并正在运行！"
else
  echo "SSH 服务重启失败，请检查配置！"
fi

############################################
# 9. 配置并启用 fail2ban
############################################
# （脚本开头已安装 fail2ban）
if [ ! -d "/etc/fail2ban" ]; then
  mkdir -p /etc/fail2ban || { echo "创建 /etc/fail2ban 目录失败，请检查权限！"; exit 1; }
fi

# 写入 fail2ban 配置
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = $RANDOM_PORT
logpath = /var/log/secure
action = iptables[name=sshd, port=$RANDOM_PORT, protocol=tcp]
EOF

# 启用并重启 fail2ban
systemctl enable fail2ban
systemctl restart fail2ban
if ! systemctl status fail2ban | grep -q "active (running)"; then
  echo "Fail2Ban 服务启动失败，请检查日志：journalctl -u fail2ban"
fi

# 确保 fail2ban 配置动态应用到 iptables
mkdir -p /etc/systemd/system/fail2ban.service.d
cat > /etc/systemd/system/fail2ban.service.d/override.conf <<EOF
[Service]
ExecStartPost=/bin/bash -c '/sbin/iptables-save > /etc/sysconfig/iptables || echo "iptables-save failed, continuing..."'
EOF

systemctl daemon-reload
systemctl restart fail2ban
if ! systemctl status fail2ban | grep -q "active (running)"; then
  echo "Fail2Ban 服务启动失败，请检查日志：journalctl -u fail2ban"
fi

############################################
# 10. 配置系统时间和时区
############################################
timedatectl set-timezone Asia/Shanghai
systemctl enable chronyd
systemctl start chronyd

############################################
# 11. 内核参数优化
############################################
cat > /etc/sysctl.conf << EOF
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
vm.swappiness = 10
fs.file-max = 2097152
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.ip_local_port_range = 1024 65000
net.core.default_qdisc = fq
EOF
sysctl -p

# 检查并设置 BBR
if sysctl net.ipv4.tcp_available_congestion_control | grep -q "bbr"; then
  sysctl -w net.ipv4.tcp_congestion_control=bbr
  echo "BBR 已启用。"
else
  modprobe tcp_bbr
  echo "tcp_bbr" >> /etc/modules-load.d/tcp_bbr.conf
  sysctl -w net.ipv4.tcp_congestion_control=bbr
  echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  echo "BBR 模块加载完成，请确认状态。"
fi

############################################
# 12. 禁用 Transparent Huge Pages
############################################
cat > /etc/systemd/system/disable-thp.service << 'EOF'
[Unit]
Description=Disable Transparent Huge Pages (THP)

[Service]
Type=simple
ExecStart=/bin/sh -c "echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled && echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag"

[Install]
WantedBy=multi-user.target
EOF
systemctl enable disable-thp
systemctl start disable-thp

############################################
# 13. 设置主机名
############################################
echo "请输入主机名称拼音："
read hname
while [ -z "$hname" ]; do
  echo "主机名称不能为空，请重新输入！"
  read hname
done
hostnamectl set-hostname "$hname"

############################################
# 14. 输出完成信息
############################################
echo "初始化完成！"
echo "Root 密码：$SUBPASS"
if [ -z "$SUBPASS2" ]; then
  # 如果已存在 monster 用户，则不会生成新密码
  echo "Monster 用户已存在。如需密码请自行重置。"
else
  echo "Monster 用户密码：$SUBPASS2"
fi
echo "随机分配的 SSH 端口：$RANDOM_PORT"
echo "外网 IP：$IP2"
echo "主机名称：$hname"
