#!/usr/bin/env bash

debconf-set-selections <<< 'mysql-server mysql-server/root_password password password'
debconf-set-selections <<< 'mysql-server mysql-server/root_password_again password password'

apt-get install -y php5 php5-mysql mysql-server

echo 'create database sqli;' | mysql -u root --password=password && echo ' [OK] DB'
echo 'create table users(id int(6) not null auto_increment PRIMARY KEY, login varchar(255), passwd varchar(255));' | mysql -u root --password=password sqli && echo ' [OK] TABLE'
echo "INSERT into users (login, passwd) VALUES ('admin', '71492d099f3b19ff08ac600c1d8f770d82d938a6');" | mysql -u root --password=password sqli && echo ' [OK] INSERT'