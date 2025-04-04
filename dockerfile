FROM php:8.2-fpm-alpine3.17 as base

# install necessary alpine packages
RUN apk update && apk add --no-cache \
        freetype-dev \
        libjpeg-turbo-dev \
        libpng-dev \
        freetype-dev \
        linux-headers\
        zip

# Enable the GD extension
RUN docker-php-ext-configure gd --with-freetype --with-jpeg

# compile native PHP packages
RUN docker-php-ext-install \
    gd \
    pcntl \
    bcmath \
    pdo_mysql


# install composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer 

# Set working directory
WORKDIR /var/www

#****************************************************************************************************************

#CODE Base Copy with Permission
FROM base as codebase

# Copy existing application directory permissions
COPY --chown=www-data:www-data ./api/ /var/www

#****************************************************************************************************************

#DEPENDENCIES
FROM codebase as dependencies

ARG COMPOSER_INSTALL_PARAM

# Copy existing application directory permissions
RUN composer install --no-interaction ${COMPOSER_INSTALL_PARAM}

#****************************************************************************************************************

#ARTISAN
FROM dependencies as artisan

CMD ["echo", "Run php artisan command."]

#****************************************************************************************************************

#APP LOCAL DEVELOPMENT ENVIRONMENT VIA DOCKER-COMPOSE
FROM dependencies as development

RUN apk add --no-cache $PHPIZE_DEPS \
    && pecl install xdebug-3.2.0 \
    && docker-php-ext-enable xdebug

RUN echo "xdebug.mode=develop,debug,coverage" > /usr/local/etc/php/conf.d/xdebug.ini

EXPOSE 9000

CMD ["php-fpm"]

#****************************************************************************************************************

#APP
FROM dependencies as production

USER www-data

EXPOSE 9000

CMD ["php-fpm"]
