USE phish_market;

-- Create `products` table
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data into `products`
INSERT INTO products (name, price) VALUES
('Atlantic Cod', 10.99),
('Pacific Salmon', 24.99),
('Catfish', 15.50),
('Tuna (Dolphin Friendly)', 7.99),
('Swordfish', 39.99),
('Tilapia', 12.75),
('Alaskan Whitefish', 29.99),
('Bass', 19.99),
('Red Snapper', 44.99);

-- Create `customers` table
CREATE TABLE IF NOT EXISTS customers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    credit_card VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data into `customers`
INSERT INTO customers (name, email, credit_card) VALUES
('John Doe', 'john@phishmarket.com', '1234567890123456'),
('Jane Smith', 'jane@phishmarket.com', '9876543210987654'),
('Adam Ant', 'adam@phishmarket.com', '8136754102587196'),
('Harry Henderson', 'harry@phishmarket.com', '3917502648193762'),
('Luke Skywalker', 'luke@phishmarket.com', '7381078297198246'),
('Jimmy Stewart', 'jimmy@phishmarket.com', '1837483210764358');

-- Create `orders` table
CREATE TABLE IF NOT EXISTS orders (
    order_number INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT NOT NULL,
    total DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);

-- Create `order_items` table to link `orders` and `products`
CREATE TABLE IF NOT EXISTS order_items (
    order_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL,
    PRIMARY KEY (order_id, product_id),
    FOREIGN KEY (order_id) REFERENCES orders(order_number),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Insert sample data into `orders` and `order_items`
INSERT INTO orders (customer_id, total) VALUES
(1, 43.97),
(2, 45.49),
(3, 15.50);

INSERT INTO order_items (order_id, product_id, quantity) VALUES
(1, 1, 1), -- Atlantic Cod
(1, 2, 1), -- Pacific Salmon
(1, 4, 1), -- Tuna (Dolphin Friendly)
(2, 3, 1), -- Catfish
(2, 7, 1), -- Alaskan Whitefish
(3, 3, 1); -- Catfish

-- Create `admin` table to store the flag
CREATE TABLE IF NOT EXISTS admin (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    flag VARCHAR(255) NOT NULL
);

-- Insert the flag into the `admin` table
INSERT INTO admin (username, flag) VALUES
('admin', 'INTIGRITI{fake_flag}');

SET GLOBAL super_read_only = ON;
