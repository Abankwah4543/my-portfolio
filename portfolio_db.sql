-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1:3306
-- Generation Time: Jul 26, 2025 at 04:06 AM
-- Server version: 8.2.0
-- PHP Version: 8.2.13

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `portfolio_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `contacts`
--

DROP TABLE IF EXISTS `contacts`;
CREATE TABLE IF NOT EXISTS `contacts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `subject` varchar(255) DEFAULT NULL,
  `message` text NOT NULL,
  `submission_date` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `contacts`
--

INSERT INTO `contacts` (`id`, `name`, `email`, `subject`, `message`, `submission_date`) VALUES
(1, 'joseph Abankwah', 'josephabankwah3@gmail.com', 'Abankwah', 'Joseph', '2025-07-26 03:07:42'),
(3, 'joseph Abankwah', 'josephabankwah3@gmail.com', 'Abankwah', 'Joseph', '2025-07-26 03:11:57'),
(4, 'joseph Abankwah', 'josephabankwah3@gmail.com', 'Abankwah', 'Joseph', '2025-07-26 03:53:01'),
(5, 'joseph Abankwah', 'josephabankwah3@gmail.com', 'Abankwah', 'Joseph', '2025-07-26 03:53:42'),
(6, 'joseph Abankwah', 'josephabankwah3@gmail.com', 'Abankwah', 'Joseph', '2025-07-26 03:54:22'),
(7, 'joseph Abankwah', 'josephabankwah3@gmail.com', 'Abankwah', 'Joseph', '2025-07-26 03:56:02');
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
