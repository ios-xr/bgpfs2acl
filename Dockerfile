FROM python:3.9-slim

WORKDIR /app/

COPY . .
RUN pip install -Ur requirements.txt

ENTRYPOINT [ "python3", "-m", "bgpfs2acl" ]