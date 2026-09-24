FROM node:22-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install

RUN python3 -m venv /opt/venv

COPY backend/presidio/requirements.txt /tmp/requirements.txt

RUN /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install -r /tmp/requirements.txt

ENV PATH="/opt/venv/bin:$PATH"

COPY . .

RUN npm run build

ENV NODE_ENV=production
ENV PRESIDIO_PORT=5001

EXPOSE 10000

CMD ["npm", "start"]