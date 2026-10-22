# Multi-stage Dockerfile fixture
FROM --platform=$BUILDPLATFORM php:8.3-fpm AS base
FROM php:8.3.10-cli-alpine AS worker
FROM nginx:1.27-alpine AS web
