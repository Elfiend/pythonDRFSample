FROM python:3.9-slim-bullseye
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED 1

ARG PORT

RUN apt-get update \
	&& apt-get install -y --no-install-recommends build-essential libpq-dev \
	&& rm -rf /var/lib/apt/lists/*

ARG DIRPATH=/app
WORKDIR ${DIRPATH}

ENV VIRTUAL_ENV /env
ENV PATH /env/bin:$PATH
COPY requirements.txt ${DIRPATH}
RUN python3 -m pip install --no-cache-dir -r requirements.txt

RUN useradd -U django_user
RUN install -d -m 0755 -o django_user -g django_user ${DIRPATH}/static

USER django_user:django_user
COPY --chown=django_user:django_user . ${DIRPATH}

CMD python3 manage.py runserver 0.0.0.0:$PORT
EXPOSE $PORT