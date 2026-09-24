FROM node:22-bookworm

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install --legacy-peer-deps

# Set up Python virtual environment
RUN python3 -m venv /opt/venv

# Install Python requirements and spaCy model
COPY backend/presidio/requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install -r /tmp/requirements.txt && \
    /opt/venv/bin/python -m spacy download en_core_web_sm

# Add venv to PATH
ENV PATH="/opt/venv/bin:$PATH"

# Copy the rest of the application files
COPY . .

# Build step
RUN npm run build

ENV NODE_ENV=production
ENV PRESIDIO_PORT=5001

EXPOSE 10000

CMD ["npm", "start"]