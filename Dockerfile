FROM python:3.10.12
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY . .
RUN python manage.py collectstatic --noinput
RUN python manage.py makemigrations
RUN python manage.py migrate
ENTRYPOINT ["bash", "-c", "python manage.py createsuperuser && admin@gmail.com && admin@gmail.com && password && password && y && python manage.py runserver 0.0.0.0:9000"]
