# Use official PHP + Apache image
FROM php:8.2-apache

# Install SQLite development libraries (REQUIRED for pdo_sqlite)
RUN apt-get update && apt-get install -y \
    libsqlite3-dev \
    sqlite3 \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Enable SQLite PDO support
RUN docker-php-ext-install pdo pdo_sqlite

# Enable Apache mod_rewrite (important for routing)
RUN a2enmod rewrite

# Copy all project files into Apache directory
COPY . /var/www/html/

# Set file permissions so SQLite database is writable
RUN chmod -R 777 /var/www/html/

# Expose port 80 to the web
EXPOSE 80

# Start Apache server
CMD ["apache2-foreground"]
