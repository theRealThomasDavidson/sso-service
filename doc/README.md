# Development Tutorial

This tutorial will guide you through the process of setting up a development environment and running a Flask application using Docker. It includes steps for setting environment variables, building a Docker image, and running the container.

## Setting Environment Variables

1. run this in the parent directory of the directory this file is in:
```powershell
    .\secret\set_env_variables.ps1    
```

1. Save the file. These environment variables will be used to configure the Flask application and connect to the MySQL database.

## Building the Docker Image

To build the Docker image for your Flask application, follow these steps:

1. Open a terminal or command prompt and navigate to the project directory.

2. Run the following command to build the Docker image:
```bash
docker build -t my-flask-app .
```

This command will build the Docker image using the `Dockerfile` in the current directory and tag it as `my-flask-app`.

## Running the Docker Container

Once you have built the Docker image, you can run it as a container using the following command:

```bash
docker run -e DB_USERNAME=root -e DB_PASSWORD=Root@123 -e DB_HOST=host.docker.internal -e DB_NAME=movie_app -p 5000:5000 -it my-flask-app
```

This command starts the Docker container with the specified environment variables and exposes port 5000 of the container to port 5000 of the host machine. You can access the Flask application by opening a web browser and navigating to `http://localhost:5000`.

Congratulations! You have successfully set up your development environment and launched the Flask application using Docker.

---

This tutorial provides a basic overview of setting up a development environment and running a Flask application using Docker. Feel free to explore further and customize the configurations to fit your specific requirements.

If you have any questions or need further assistance, don't hesitate to ask.
