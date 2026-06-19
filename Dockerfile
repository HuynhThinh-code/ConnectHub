FROM php:7.4-apache

RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    exiftool \
    curl \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install gd mysqli pdo pdo_mysql \
    && a2enmod rewrite

# Fix: AH00534: apache2: Configuration error: More than one MPM loaded
RUN a2dismod mpm_event || true
RUN a2dismod mpm_worker || true
RUN a2enmod mpm_prefork || true

# Disable security headers for lab purposes
RUN echo "ServerTokens Full" >> /etc/apache2/apache2.conf
RUN echo "expose_php = On" >> /usr/local/etc/php/php.ini

COPY ./app /var/www/html/
RUN chown -R www-data:www-data /var/www/html/uploads
RUN chmod -R 777 /var/www/html/uploads

EXPOSE 80
