-- phpMyAdmin SQL Dump
-- version 5.1.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1:3306
-- Generation Time: Sep 13, 2022 at 08:16 PM
-- Server version: 8.0.27
-- PHP Version: 7.4.26

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `dedb`
--CREATE TABLE `case` (`caseID` int NOT NULL AUTO_INCREMENT PRIMARY KEY, `name` VARCHAR(255) NOT NULL, `status` int NOT NULL, `datecreated` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP);
--DROP TABLE IF EXISTS `evidence`;
-- CREATE TABLE IF NOT EXISTS `case` (
--   `caseID` int NOT NULL AUTO_INCREMENT PRIMARY KEY,
--   `name` varchar(255) NOT NULL,
--   `status` varchar(6) NOT NULL,
--   `dateCreated` datetime NOT NULL
-- ) ENGINE=InnoDB AUTO_INCREMENT=1113 DEFAULT CHARSET=utf8mb4;
-- --------------------------------------------------------

--
-- Table structure for table `case`
--

DROP TABLE IF EXISTS `case_file`;
CREATE TABLE IF NOT EXISTS `case_file` (
  `caseID` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `status` varchar(6) NOT NULL,
  `datecreated` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`caseID`)
) ENGINE=InnoDB AUTO_INCREMENT=11111113 DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `case`
--

INSERT INTO `case_file` (`caseID`, `name`, `status`,`datecreated`) VALUES
(11111111, 'Case ones', 'Open', '2022-08-26 06:34:59'),
(11111112, 'Case ones and a two', 'Closed', '2022-08-26 06:34:59');

-- --------------------------------------------------------

--
-- Table structure for table `evidence`
--

DROP TABLE IF EXISTS `evidence`;
CREATE TABLE IF NOT EXISTS `evidence` (
  `evidenceID` int NOT NULL AUTO_INCREMENT,
  `caseID` int NOT NULL,
  `filename` varchar(255) NOT NULL,
  `hash` varchar(46) NOT NULL,
  `timestamp` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`evidenceID`),
  KEY `caseID` (`caseID`)
) ENGINE=InnoDB AUTO_INCREMENT=1113 DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `evidence`
--

INSERT INTO `evidence` (`evidenceID`, `caseID`, `filename`, `hash`, `timestamp`) VALUES
(1111, 11111111, 'test.txt', 'QmTcnhtLFN6kDQRFuFyVxuvtZiynDVJuutiNoScWpCZgYJ', '2022-10-12 13:48:31'),
(1112, 11111112, 'text2.html', 'QmWH5JgfatqVoh8Xv88xqfifLhBdPH9TEkWDERshnsYWZU', '2022-10-12 13:48:31'),
(1113, 11111111, 'web-s', 'QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH', '2022-10-12 13:50:02'),
(1114, 11111112, '0bd05023e5fa1a80b5a98c178ddc1865.jpg', 'Qme47NLWoLYRWEeSPVqiVgYh32mx4TtQfEydtYDUQbeb1p', '2022-10-12 14:26:15'),
(1115, 11111112, 'STUDY_GUIDE_-_Example_1_esther_namirembe_11.doc', 'QmSfK1EAhqjgyLAbxGBtnyu8xdvjPB4tuG3UK3FeHkLgLJ', '2022-10-12 14:38:45');


--
-- Table structure for table `logs_activity`
--

DROP TABLE IF EXISTS `logs_activity`;
CREATE TABLE IF NOT EXISTS `logs_activity` (
  `logID` int NOT NULL AUTO_INCREMENT,
  `subject` varchar(255) NOT NULL,
  `userID` int NOT NULL,
  `method` text NOT NULL,
  PRIMARY KEY (`logID`),
  KEY `userID` (`userID`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `logs_activity`
--

INSERT INTO `logs_activity` (`logID`, `subject`, `userID`, `method`) VALUES
(1, 'Added evidence', 1, 'insert'),
(2, 'added', 2, 'insert');

-- --------------------------------------------------------

--
-- Table structure for table `report`
--

DROP TABLE IF EXISTS `report`;
CREATE TABLE IF NOT EXISTS `report` (
  `reportID` int NOT NULL AUTO_INCREMENT,
  `caseID` int NOT NULL,
  `evidenceID` int NOT NULL,
  `userID` int NOT NULL,
  `data` varchar(255) NOT NULL,
  PRIMARY KEY (`reportID`),
  KEY `caseID` (`caseID`),
  KEY `userID` (`userID`),
  KEY `evidenceID` (`evidenceID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `report`
--

INSERT INTO `report` (`reportID`, `caseID`, `userID`, `evidenceID`, `data`) VALUES
(1, 11111111, 1,1111, 'Well thats alot of evidence');

-- --------------------------------------------------------

--
-- Table structure for table `role`
--

DROP TABLE IF EXISTS `role`;
CREATE TABLE IF NOT EXISTS `role` (
  `roleID` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`roleID`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `role`
--

INSERT INTO `role` (`roleID`, `name`) VALUES
(0, 'Investigator'),
(1, 'Analyst'),
(2, 'Chief Investigator'),
(3, 'Admin');

-- --------------------------------------------------------

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
CREATE TABLE IF NOT EXISTS `user` (
  `userID` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password` varchar(50) NOT NULL,
  `roleID` int(1) NOT NULL,
  PRIMARY KEY (`userID`),
  KEY `roleID` (`roleID`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `user`
--

INSERT INTO `user` (`userID`, `username`, `email`, `password`, `roleID`) VALUES
(1, 'kcalvinroy','kcalvinroy@gmail.com', '135f4cf668f6d13bfe444932a873a310', 3),
(2, 'luireaganz','luireaganz@gmail.com', '135f4cf668f6d13bfe444932a873a310', 2),
(3, 'agabaraymond','agabaraymond@gmail.com', '135f4cf668f6d13bfe444932a873a310', 0),
(4, 'katushabejoan','katushabejoan@gmail.com', '135f4cf668f6d13bfe444932a873a310', 1);



--
-- Table structure for table `assigned`
--

DROP TABLE IF EXISTS `assigned`;
CREATE TABLE IF NOT EXISTS `assigned` (
  `caseID` int NOT NULL,
  `userID` int NOT NULL,
  KEY `caseID` (`caseID`),
  KEY `userID` (`userID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `assigned`
--

INSERT INTO `assigned` (`caseID`, `userID`) VALUES
(11111111, 3),
(11111112, 4);


--
-- Constraints for dumped tables
--

--
-- Constraints for table `case`
--
ALTER TABLE `case_file`
  ADD CONSTRAINT `case_ibfk_1` FOREIGN KEY (`userID`) REFERENCES `user` (`userID`) ON DELETE RESTRICT ON UPDATE RESTRICT;

--
-- Constraints for table `evidence`
--
ALTER TABLE `evidence`
  ADD CONSTRAINT `evidence_ibfk_1` FOREIGN KEY (`caseID`) REFERENCES `case_file` (`caseID`) ON DELETE RESTRICT ON UPDATE RESTRICT;

--
-- Constraints for table `logs_activity`
--
ALTER TABLE `logs_activity`
  ADD CONSTRAINT `logs_activity_ibfk_1` FOREIGN KEY (`userID`) REFERENCES `user` (`userID`) ON DELETE RESTRICT ON UPDATE RESTRICT;

--
-- Constraints for table `report`
--
ALTER TABLE `report`
  ADD CONSTRAINT `report_ibfk_1` FOREIGN KEY (`caseID`) REFERENCES `case_file` (`caseID`) ON DELETE RESTRICT ON UPDATE RESTRICT,
  ADD CONSTRAINT `report_ibfk_2` FOREIGN KEY (`userID`) REFERENCES `user` (`userID`) ON DELETE RESTRICT ON UPDATE RESTRICT,
  ADD CONSTRAINT `report_ibfk_3` FOREIGN KEY (`evidenceID`) REFERENCES `evidence` (`evidenceID`) ON DELETE RESTRICT ON UPDATE RESTRICT;

--
-- Constraints for table `assigned`
--
ALTER TABLE `assigned`
  ADD CONSTRAINT `assigned_ibfk_1` FOREIGN KEY (`caseID`) REFERENCES `case_file` (`caseID`) ON DELETE RESTRICT ON UPDATE RESTRICT,
  ADD CONSTRAINT `assigned_ibfk_2` FOREIGN KEY (`userID`) REFERENCES `user` (`userID`) ON DELETE RESTRICT ON UPDATE RESTRICT;

--
-- Constraints for table `user`
--
ALTER TABLE `user`
  ADD CONSTRAINT `user_ibfk_1` FOREIGN KEY (`roleID`) REFERENCES `role` (`roleID`) ON DELETE RESTRICT ON UPDATE RESTRICT;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;

show tables;

select * from user;

select * from role;

select * from case_file;

select * from evidence;

select * from report;

select * from logs_activity;

