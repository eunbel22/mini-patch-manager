# 화면 이미지: 1단계에서 React를 빌드하고, 2단계에서 결과(정적 파일)만 Nginx에 담는다.
FROM node:24-alpine AS build
WORKDIR /app
# package.json이 그대로면 설치 층은 다시 만들지 않는다(캐시)
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
# 패치 파일 내려받기 제한의 기본값: 연결당 초당 1MB, 같은 주소에서 동시에 2개. compose 환경변수로 바꾼다.
ENV PATCH_RATE_LIMIT=1m \
    PATCH_MAX_CONN=2
# 이 이미지는 시작할 때 /etc/nginx/templates/*.template의 ${변수}를 환경변수로 바꿔 conf.d/에 설정 파일을 만든다
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
