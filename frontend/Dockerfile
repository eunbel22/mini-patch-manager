# 화면 이미지: 1단계에서 React를 빌드하고, 2단계에서 결과(정적 파일)만 Nginx에 담는다.
FROM node:24-alpine AS build
WORKDIR /app
# package.json이 그대로면 설치 층은 다시 만들지 않는다(캐시)
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
