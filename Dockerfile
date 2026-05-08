FROM public.ecr.aws/amazonlinux/amazonlinux:2023

WORKDIR /app

RUN dnf update -y && \
    dnf install -y python3.11 python3.11-pip && \
    ln -sf /usr/bin/python3.11 /usr/bin/python3 && \
    ln -sf /usr/bin/pip3.11 /usr/bin/pip3

RUN pip3 install uv

COPY pyproject.toml ./
RUN uv pip install --system --no-cache .

COPY agent.py ./
COPY tools/ ./tools/

EXPOSE 8080
CMD ["python3", "agent.py"]
