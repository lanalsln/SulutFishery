-- ═══════════════════════════════════════════════════════════════════════════════
--  SULUT FISHERY DATABASE
--  System Jual-Beli Ikan Sederhana
--  Version: 1.0
--  Author: Sulut Fishery Dev
-- ═══════════════════════════════════════════════════════════════════════════════

-- ════════════════════════════════════════════════════════════════════════════════
-- 1. DROP DATABASE JIKA SUDAH ADA (OPTIONAL - GUNAKAN JIKA INGIN RESET)
-- ════════════════════════════════════════════════════════════════════════════════
-- DROP DATABASE IF EXISTS `sulutfishery`;

-- ════════════════════════════════════════════════════════════════════════════════
-- 2. BUAT DATABASE BARU
-- ════════════════════════════════════════════════════════════════════════════════
CREATE DATABASE IF NOT EXISTS `sulutfishery` 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

-- ════════════════════════════════════════════════════════════════════════════════
-- 3. GUNAKAN DATABASE
-- ════════════════════════════════════════════════════════════════════════════════
USE `sulutfishery`;

-- ════════════════════════════════════════════════════════════════════════════════
-- 4. BUAT SEMUA TABLE
-- ════════════════════════════════════════════════════════════════════════════════

-- ── USERS TABLE ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(100) NOT NULL,
  `email` VARCHAR(100) UNIQUE NOT NULL,
  `phone` VARCHAR(20) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `address` TEXT,
  `city` VARCHAR(60),
  `province` VARCHAR(60),
  `balance` DECIMAL(15, 2) DEFAULT 0.00,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_email (email),
  INDEX idx_created_at (created_at)
);

-- ── POSTS TABLE (Listing Penjualan Ikan) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS `posts` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NOT NULL,
  `product_name` VARCHAR(150) NOT NULL,
  `description` TEXT,
  `category` VARCHAR(50),
  `location` VARCHAR(100) NOT NULL,
  `quantity` DECIMAL(10, 2) NOT NULL,
  `unit` VARCHAR(20) DEFAULT 'kg',
  `price_per_unit` DECIMAL(12, 2) NOT NULL,
  `total_price` DECIMAL(15, 2) NOT NULL,
  `photo` VARCHAR(255),
  `status` ENUM('active', 'sold', 'cancelled') DEFAULT 'active',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_id (user_id),
  INDEX idx_status (status),
  INDEX idx_created_at (created_at)
);

-- ── PURCHASES TABLE (Pembelian) ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `purchases` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `post_id` INT NOT NULL,
  `seller_id` INT NOT NULL,
  `buyer_id` INT NOT NULL,
  `quantity_bought` DECIMAL(10, 2) NOT NULL,
  `price_per_unit` DECIMAL(12, 2) NOT NULL,
  `total_amount` DECIMAL(15, 2) NOT NULL,
  `payment_status` ENUM('pending', 'completed', 'cancelled') DEFAULT 'pending',
  `delivery_status` ENUM('pending', 'shipped', 'delivered') DEFAULT 'pending',
  `notes` TEXT,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (buyer_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_seller_id (seller_id),
  INDEX idx_buyer_id (buyer_id),
  INDEX idx_post_id (post_id),
  INDEX idx_created_at (created_at)
);

-- ── TRANSACTION LOG TABLE ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `transactions` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `purchase_id` INT,
  `user_id` INT NOT NULL,
  `type` ENUM('sale', 'purchase') NOT NULL,
  `amount` DECIMAL(15, 2) NOT NULL,
  `description` VARCHAR(255),
  `reference_type` VARCHAR(50),
  `reference_id` INT,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (purchase_id) REFERENCES purchases(id) ON DELETE SET NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_id (user_id),
  INDEX idx_created_at (created_at)
);

-- ════════════════════════════════════════════════════════════════════════════════
-- 5. TAMBAH INDEXES UNTUK PERFORMA
-- ════════════════════════════════════════════════════════════════════════════════

ALTER TABLE `posts` ADD INDEX idx_product_name (product_name);
ALTER TABLE `purchases` ADD INDEX idx_payment_status (payment_status);
ALTER TABLE `purchases` ADD INDEX idx_delivery_status (delivery_status);

-- ════════════════════════════════════════════════════════════════════════════════
-- 6. INSERT SAMPLE DATA (UNTUK TESTING)
-- ════════════════════════════════════════════════════════════════════════════════

-- Sample User 1 (Penjual)
-- Password: penjual123
-- Hash: $2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86E36gZvWFm
INSERT INTO `users` (`name`, `email`, `phone`, `password`, `address`, `city`, `province`, `balance`, `created_at`) VALUES 
('Budi Santoso', 'budi@fishery.com', '085123456789', '$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86E36gZvWFm', 'Jl. Pantai No. 123', 'Manado', 'Sulawesi Utara', 5000000, NOW());

-- Sample User 2 (Penjual)
-- Password: leman456
INSERT INTO `users` (`name`, `email`, `phone`, `password`, `address`, `city`, `province`, `balance`, `created_at`) VALUES 
('Leman Kusuma', 'leman@fishery.com', '085987654321', '$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86E36gZvWFm', 'Jl. Nelayan No. 456', 'Bitung', 'Sulawesi Utara', 3000000, NOW());

-- Sample User 3 (Pembeli)
-- Password: pembeli789
INSERT INTO `users` (`name`, `email`, `phone`, `password`, `address`, `city`, `province`, `balance`, `created_at`) VALUES 
('Ahmad Wijaya', 'ahmad@buyer.com', '081234567890', '$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86E36gZvWFm', 'Jl. Merdeka No. 789', 'Manado', 'Sulawesi Utara', 2000000, NOW());

-- Sample User 4 (Pembeli)
-- Password: pembeli000
INSERT INTO `users` (`name`, `email`, `phone`, `password`, `address`, `city`, `province`, `balance`, `created_at`) VALUES 
('Siti Nurhaliza', 'siti@buyer.com', '082345678901', '$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86E36gZvWFm', 'Jl. Sudirman No. 321', 'Tomohon', 'Sulawesi Utara', 1500000, NOW());

-- Sample Listing dari Budi (user_id=1)
INSERT INTO `posts` (`user_id`, `product_name`, `description`, `category`, `location`, `quantity`, `unit`, `price_per_unit`, `total_price`, `status`, `created_at`) VALUES 
(1, 'Ikan Cakalang Segar', 'Ikan cakalang berkualitas tinggi, segar dari laut', 'Ikan Kering', 'Manado', 50, 'kg', 150000, 7500000, 'active', NOW()),
(1, 'Ikan Tuna Premium', 'Tuna segar premium pilihan, cocok untuk sushi', 'Ikan Segar', 'Manado', 30, 'kg', 200000, 6000000, 'active', NOW()),
(1, 'Teri Nasi Berkualitas', 'Teri nasi kering, gurih dan berkualitas', 'Ikan Kering', 'Manado', 100, 'kg', 80000, 8000000, 'active', NOW());

-- Sample Listing dari Leman (user_id=2)
INSERT INTO `posts` (`user_id`, `product_name`, `description`, `category`, `location`, `quantity`, `unit`, `price_per_unit`, `total_price`, `status`, `created_at`) VALUES 
(2, 'Ikan Bandeng Segar', 'Bandeng segar pilihan dari tangkapan pagi', 'Ikan Segar', 'Bitung', 40, 'kg', 120000, 4800000, 'active', NOW()),
(2, 'Udang Besar Segar', 'Udang lokal segar, ukuran besar dan merah', 'Seafood', 'Bitung', 25, 'kg', 250000, 6250000, 'active', NOW());

-- Sample Pembelian
INSERT INTO `purchases` (`post_id`, `seller_id`, `buyer_id`, `quantity_bought`, `price_per_unit`, `total_amount`, `payment_status`, `delivery_status`, `notes`, `created_at`) VALUES 
(1, 1, 3, 10, 150000, 1500000, 'completed', 'delivered', 'Untuk kebutuhan restoran', NOW()),
(2, 1, 4, 5, 200000, 1000000, 'completed', 'delivered', 'Untuk pesta', NOW()),
(4, 2, 3, 8, 120000, 960000, 'completed', 'delivered', 'Pembelian malam hari', NOW());

-- Sample Transaction Log
INSERT INTO `transactions` (`purchase_id`, `user_id`, `type`, `amount`, `description`, `reference_type`, `reference_id`, `created_at`) VALUES 
(1, 3, 'purchase', 1500000, 'Pembelian Ikan Cakalang Segar', 'purchase', 1, NOW()),
(1, 1, 'sale', 1500000, 'Penjualan Ikan Cakalang Segar', 'sale', 1, NOW()),
(2, 4, 'purchase', 1000000, 'Pembelian Ikan Tuna Premium', 'purchase', 2, NOW()),
(2, 1, 'sale', 1000000, 'Penjualan Ikan Tuna Premium', 'sale', 2, NOW()),
(3, 3, 'purchase', 960000, 'Pembelian Ikan Bandeng Segar', 'purchase', 3, NOW()),
(3, 2, 'sale', 960000, 'Penjualan Ikan Bandeng Segar', 'sale', 3, NOW());

-- ════════════════════════════════════════════════════════════════════════════════
-- 7. VERIFIKASI DATA (JALANKAN QUERIES INI UNTUK CEK DATA)
-- ════════════════════════════════════════════════════════════════════════════════

-- SELECT COUNT(*) as 'Total Users' FROM users;
-- SELECT COUNT(*) as 'Total Posts/Listings' FROM posts;
-- SELECT COUNT(*) as 'Total Purchases' FROM purchases;
-- SELECT COUNT(*) as 'Total Transactions' FROM transactions;

-- ════════════════════════════════════════════════════════════════════════════════
--  ✅ SETUP DATABASE SELESAI!
--  SEMUA TABLE SUDAH DIBUAT DENGAN FOREIGN KEYS DAN SAMPLE DATA
-- ════════════════════════════════════════════════════════════════════════════════
