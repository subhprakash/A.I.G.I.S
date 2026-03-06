import docker

client = docker.from_env()


def run_tool(container_image, command, mount):

    container = client.containers.run(
        container_image,
        command,
        volumes={
            mount: {
                "bind": "/scan",
                "mode": "ro"
            }
        },
        remove=True,
        stdout=True,
        stderr=True
    )

    return container.decode()