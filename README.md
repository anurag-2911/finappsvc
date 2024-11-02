# FinApp Microservices Architecture

## Introduction

FinApp is a microservices-based application designed to handle financial services, including user authentication, finance applications, analytics, and notifications. The application is structured into four core backend microservices, each responsible for a specific domain:

- **Auth Service**
- **Finance Service**
- **Analytics Service**
- **Notification Service**

A common helper package, **`common`**, provides shared utilities such as JWT handling, MongoDB connections, and RabbitMQ message publishing.

**Repository**: The source code for FinApp is available on GitHub:

[https://github.com/anurag-2911/finappsvc](https://github.com/anurag-2911/finappsvc)

Feel free to clone the repository, explore the code, and contribute to the project by creating issues or pull requests.

## Architecture Overview

The application leverages a microservices architecture to promote scalability, maintainability, and independent deployment of services. The services communicate asynchronously using **RabbitMQ** as a message broker and store data in **MongoDB** databases.


![arch-diagram](https://github.com/user-attachments/assets/ea37b6fb-94d8-4e3e-a29a-722d3ac89671)


## Services

### Auth Service

**Purpose**: Handles user authentication, including sign-up and login functionalities.

**Key Endpoints**:

- `POST /signup`: Registers a new user by hashing the password and storing user credentials in MongoDB. Generates a JWT access token upon successful registration.
- `POST /login`: Authenticates a user by verifying the password against the stored hash. Generates a JWT access token upon successful login.

**Workflow**:

1. **User Registration**:
   - Receives user credentials.
   - Checks if the user already exists in MongoDB.
   - Hashes the password using bcrypt.
   - Stores the user in the `users` collection.
   - Generates a JWT token.
   - Publishes a `user_registered` message to RabbitMQ with the token.

2. **User Login**:
   - Receives login credentials.
   - Fetches user data from MongoDB.
   - Verifies the password using bcrypt.
   - Generates a JWT token.
   - Publishes a `user_activity` message to RabbitMQ with the token.

### Finance Service

**Purpose**: Manages finance applications, financing options, and provides dashboard information.

**Key Endpoints**:

- `POST /apply`: Allows authenticated users to submit finance applications.
- `GET /status`: Retrieves the status of finance applications for the current user.
- `PUT /update_status/{user}/{status}`: Updates the status of a user's application (admin only).
- `GET /dashboard-info`: Provides a summary of a user's finance applications.
- `GET /financing-options`: Retrieves available financing options.
- `POST /select-financing-option`: Allows users to select a financing option.
- `GET /admin/applications`: Fetches all finance applications (admin panel) with pagination.
- `PUT /admin/update_status/{application_id}/{status}`: Updates application status by admin.

**Workflow**:

- **Finance Application**:
  - Authenticates the user via JWT.
  - Accepts application details and stores them in MongoDB.
  - Publishes an `application_submitted` message to RabbitMQ.

- **Admin Functions**:
  - Verifies if the current user is an admin.
  - Allows admin users to view and update all finance applications.

### Analytics Service

**Purpose**: Provides analytics data for admin users, summarizing user activities and finance applications.

**Key Endpoints**:

- `GET /analytics`: Retrieves analytics data (admin only).

**Workflow**:

- Authenticates the user via JWT.
- Verifies admin privileges.
- Fetches analytics data from MongoDB.
- Summarizes data such as total events, logins per user, and financing checks per user.

### Notification Service

**Purpose**: Listens to RabbitMQ message queues and logs events into MongoDB for analytics purposes.

**Key Queues**:

- `application_submitted`
- `user_activity`

**Workflow**:

- **Message Consumption**:
  - Connects to RabbitMQ and listens to specified queues.
  - Authenticates incoming messages using JWT tokens in message headers.
  - Logs events into the `user_analytics` collection in MongoDB.

## Common Package

The `common` package contains shared utilities used across services:

- **JWT Handler**: Manages JWT token creation and verification.
- **MongoDB Handler**: Provides a connection to the MongoDB client.
- **RabbitMQ Handler**: Manages publishing messages to RabbitMQ queues.

## Technology Stack

- **FastAPI**: Web framework for building APIs.
- **MongoDB**: NoSQL database for data storage.
- **RabbitMQ**: Message broker for asynchronous communication between services.
- **JWT**: JSON Web Tokens for authentication.
- **bcrypt**: Library for hashing passwords.
- **Docker**: Containerization platform for packaging services.
- **Kubernetes**: Orchestrates containerized applications.
- **Nginx Ingress Controller**: Manages external access to services in a Kubernetes cluster.
- **GitHub Actions**: CI/CD pipeline for automated builds and deployments.

## Message Queue (RabbitMQ)

**Why RabbitMQ?**

- **Asynchronous Communication**: Decouples services and allows them to communicate without blocking.
- **Scalability**: Enables the system to handle high loads by distributing tasks across services.
- **Reliability**: Ensures messages are delivered even if a service is temporarily unavailable.

**Usage in FinApp**:

- **Event Publishing**: Services publish events to RabbitMQ queues when significant actions occur (e.g., user login, application submission).
- **Event Consumption**: The Notification Service consumes these events and processes them accordingly, such as logging for analytics.

**Queues Used**:

- `user_registered`
- `application_submitted`
- `user_activity`
- `financing_option_selected`

## Database (MongoDB)

**Why MongoDB?**

- **Flexibility**: Schema-less design allows for easy evolution of data models.
- **Scalability**: Designed to scale horizontally across multiple servers.
- **Performance**: Optimized for read and write operations, suitable for high-traffic applications.

**Usage in FinApp**:

- **User Data**: Stores user credentials and profiles in the `users` collection.
- **Applications**: Stores finance applications in the `applications` collection.
- **Analytics**: Logs user activities and events in the `user_analytics` collection.
- **Financing Options**: Stores available financing options in the `financing_options` collection.

## Deployment and Infrastructure

### Containerization with Docker

Each microservice in FinApp is containerized using Docker. This ensures consistency across development, testing, and production environments.

**Sample Dockerfile**:

```dockerfile
# Use the official Python image
FROM python:3.9

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Start FastAPI using Uvicorn
CMD ["uvicorn", "financesvc:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
```

**Explanation**:

- **Base Image**: Uses Python 3.9 official image.
- **Working Directory**: Sets `/app` as the working directory.
- **Copy Files**: Copies application code into the container.
- **Install Dependencies**: Installs required Python packages.
- **Run Application**: Starts the FastAPI application using Uvicorn.

### Deployment with Kubernetes

The containerized services are deployed on a Kubernetes cluster. Kubernetes manages the deployment, scaling, and networking of the containerized applications.

**Key Kubernetes Resources**:

- **Deployments**: Define the desired state for replicas of the application.
- **Services**: Expose the application on a network.
- **Ingress**: Manages external access to the services.

#### Sample Deployment and Service YAML (Analytics Service)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: analytics-service
spec:
  replicas: 1
  selector:
    matchLabels:
      app: analytics-service
  template:
    metadata:
      labels:
        app: analytics-service
    spec:
      containers:
      - name: analytics-service
        image: your_dockerhub_username/analytics-service:latest
        ports:
        - containerPort: 8000  # Analytics service port
        env:
        - name: MONGODB_URI
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: MONGODB_URI
        - name: JWT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: JWT_SECRET_KEY
---
apiVersion: v1
kind: Service
metadata:
  name: analytics-service
spec:
  selector:
    app: analytics-service
  ports:
  - protocol: TCP
    port: 8004  # Expose the analytics service on port 8004
    targetPort: 8000  # Map to the container's port
  type: ClusterIP
```

**Explanation**:

- **Deployment**:
  - **Replicas**: Specifies the number of pod replicas.
  - **Containers**: Defines the container image and ports.
  - **Environment Variables**: Uses Kubernetes secrets for sensitive data.
- **Service**:
  - **Selector**: Matches the pods with the label `app: analytics-service`.
  - **Ports**: Exposes the service internally within the cluster.

### Ingress for Routing

An Ingress resource is used to manage external access to the services in the cluster. It provides URL routing, SSL termination, and load balancing.

**Sample Ingress YAML**:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: finapp-ingress
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"  # Use the ClusterIssuer
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - appsxyzabc.com
      secretName: appsxyzabc-tls
  rules:
    - host: appsxyzabc.com
      http:
        paths:
          - path: /login
            pathType: Exact
            backend:
              service:
                name: auth-service
                port:
                  number: 8001
          - path: /signup
            pathType: Exact
            backend:
              service:
                name: auth-service
                port:
                  number: 8001
          - path: /analytics
            pathType: Exact
            backend:
              service:
                name: analytics-service
                port:
                  number: 8004
          - path: /apply
            pathType: Exact
            backend:
              service:
                name: finance-service
                port:
                  number: 8002
          # Additional paths...
```

**Explanation**:

- **Ingress Controller**: Uses Nginx Ingress Controller (`ingressClassName: nginx`).
- **TLS Configuration**: Integrates with Cert-Manager for automatic Let's Encrypt certificates.
- **Routing Rules**:
  - Defines paths and routes them to the corresponding services.
  - Exposes services externally via the specified domain.

### Continuous Integration and Deployment (CI/CD) with GitHub Actions

FinApp utilizes GitHub Actions for CI/CD to automate the build and deployment processes of the microservices.

**Trigger Mechanism**:

- **Manual Trigger**: The workflow is triggered manually using `workflow_dispatch`. This allows for controlled deployments.

**Sample GitHub Actions Workflow (`build-microservices.yml`)**:

```yaml
name: Build and Push Microservices

on:
  workflow_dispatch:

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        service: [auth-service, finance-service, notification-service, analytics-service]  

    steps:
      - name: Checkout repository
        uses: actions/checkout@v2

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Log in to Docker Hub
        uses: docker/login-action@v2
        with:
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_PASSWORD }}

      - name: Copy common folder into each service
        run: |
          cp -r ./common ./auth-service/common
          cp -r ./common ./finance-service/common
          cp -r ./common ./notification-service/common
          cp -r ./common ./analytics-service/common

      - name: Build and push ${{ matrix.service }} Docker image
        run: |
          docker build -t your_dockerhub_username/${{ matrix.service }}:${{ github.sha }} -t your_dockerhub_username/${{ matrix.service }}:latest ./${{ matrix.service }}
          docker push your_dockerhub_username/${{ matrix.service }}:${{ github.sha }}
          docker push your_dockerhub_username/${{ matrix.service }}:latest
```

**Explanation**:

- **Trigger**:
  - The workflow is manually triggered via the GitHub Actions interface using `workflow_dispatch`.

- **Jobs**:
  - **build-and-push**: Builds and pushes Docker images for each microservice.
  - **Strategy Matrix**: Iterates over the list of services to build them individually.

- **Steps**:
  - **Checkout Repository**: Clones the repository to the runner.
  - **Set Up Docker Buildx**: Sets up Docker Buildx for building multi-platform images.
  - **Log in to Docker Hub**: Uses secrets `DOCKER_USERNAME` and `DOCKER_PASSWORD` for authentication.
  - **Copy Common Folder**: Copies the shared `common` directory into each service directory.
  - **Build and Push Docker Images**:
    - Builds Docker images for each service with tags based on the Git commit SHA and `latest`.
    - Pushes the images to Docker Hub.

**Benefits**:

- **Automation**: Reduces manual intervention in the build and deployment process.
- **Consistency**: Ensures that all microservices are built and deployed using the same process.
- **Scalability**: Easily extendable to include more services or steps as needed.

### Secure Communication with TLS

- **Cert-Manager**: Automates the management and issuance of TLS certificates from Let's Encrypt.
- **Annotations**: Instructs the Ingress resource to use a specific ClusterIssuer.
- **TLS Section**: Specifies the hosts and the secret name containing the TLS certificate.

### Environment Variables and Secrets

Sensitive information such as database URIs and JWT secret keys are managed using Kubernetes Secrets.

**Sample Secret YAML**:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
data:
  MONGODB_URI: base64_encoded_mongodb_uri
  JWT_SECRET_KEY: base64_encoded_jwt_secret_key
```

**Explanation**:

- **Type**: Opaque, indicating a generic secret.
- **Data**: Contains key-value pairs, where values are base64 encoded.

### Deployment Steps

1. **Build Docker Images**:

   ```bash
   # Navigate to each service directory and build images
   docker build -t your_dockerhub_username/auth-service:latest ./auth-service
   docker build -t your_dockerhub_username/finance-service:latest ./finance-service
   docker build -t your_dockerhub_username/analytics-service:latest ./analytics-service
   docker build -t your_dockerhub_username/notification-service:latest ./notification-service
   ```

2. **Push Docker Images to Registry**:

   ```bash
   docker push your_dockerhub_username/auth-service:latest
   docker push your_dockerhub_username/finance-service:latest
   # Repeat for other services
   ```

3. **Apply Kubernetes Configurations**:

   ```bash
   kubectl apply -f finappsvc/infra/
   ```

4. **Verify Deployments**:

   ```bash
   kubectl get pods
   kubectl get services
   kubectl get ingress
   ```

## Installation and Setup

### Prerequisites

- **Python 3.8+**
- **Docker**
- **Kubernetes Cluster**
- **Kubectl and Kubeconfig**: For interacting with the Kubernetes cluster.
- **Cert-Manager**: For managing TLS certificates.
- **MongoDB Instance**
- **RabbitMQ Server**
- **GitHub Account**: For CI/CD pipeline.
- **Environment Variables**:
  - `MONGODB_URI`: MongoDB connection string.
  - `RABBITMQ_URI`: RabbitMQ connection string.
  - `JWT_SECRET_KEY`: Secret key for JWT token encoding.
  - `ACCESS_TOKEN_EXPIRE_MINUTES`: Token expiration time in minutes.

### Local Development Setup

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/anurag-2911/finappsvc.git
   cd finappsvc
   ```

2. **Set Up Virtual Environment**:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables**:

   Create a `.env` file in the root directory:

   ```env
   MONGODB_URI=mongodb://localhost:27017
   RABBITMQ_URI=amqp://guest:guest@localhost:5672/
   JWT_SECRET_KEY=your_secret_key
   ACCESS_TOKEN_EXPIRE_MINUTES=30
   ```

5. **Run Services Locally**:

   Each service can be run independently. For example:

   ```bash
   # Run Auth Service
   uvicorn auth-service.authsvc:app --reload --port 8000

   # Run Finance Service
   uvicorn finance-service.financesvc:app --reload --port 8001

   # Run Analytics Service
   uvicorn analytics-service.analyticssvc:app --reload --port 8002

   # Run Notification Service
   python notification-service.notificationsvc.py
   ```

### Kubernetes Deployment Setup

1. **Set Up Kubernetes Cluster**:

   - Use a managed Kubernetes service (e.g., GKE, EKS, AKS) or set up a local cluster using Minikube or Kind.

2. **Install Nginx Ingress Controller**:

   ```bash
   kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.0.0/deploy/static/provider/cloud/deploy.yaml
   ```

3. **Install Cert-Manager**:

   ```bash
   kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.5.3/cert-manager.yaml
   ```

4. **Create Kubernetes Secrets**:

   ```bash
   kubectl create secret generic app-secrets \
     --from-literal=MONGODB_URI='mongodb://mongo_service:27017' \
     --from-literal=JWT_SECRET_KEY='your_jwt_secret_key'
   ```

5. **Deploy MongoDB and RabbitMQ**:

   - You can deploy MongoDB and RabbitMQ in the cluster using Helm charts or Kubernetes manifests.

6. **Apply Deployment Manifests**:

   ```bash
   kubectl apply -f finappsvc/infra/
   ```

7. **Verify Deployments and Services**:

   ```bash
   kubectl get deployments
   kubectl get services
   kubectl get pods
   kubectl get ingress
   ```

8. **Set Up GitHub Actions Secrets**:

   - In your GitHub repository, navigate to `Settings` > `Secrets` > `Actions`.
   - Add the following secrets:
     - `DOCKER_USERNAME`: Your Docker Hub username.
     - `DOCKER_PASSWORD`: Your Docker Hub password.

## API Endpoints

### Auth Service

- `POST /signup`: Register a new user.

  **Request Body**:

  ```json
  {
    "username": "john_doe",
    "password": "secure_password"
  }
  ```

- `POST /login`: Authenticate a user.

  **Request Body**:

  ```json
  {
    "username": "john_doe",
    "password": "secure_password"
  }
  ```

### Finance Service

- `POST /apply`: Submit a finance application.

  **Request Body**:

  ```json
  {
    "loan_types": ["personal", "mortgage"],
    "amount": 50000,
    "purpose": "Home renovation"
  }
  ```

- `GET /status`: Check the status of finance applications.

- `GET /financing-options`: Retrieve available financing options.

- `POST /select-financing-option`: Select a financing option.

  **Request Body**:

  ```json
  {
    "option_id": "60f7f9a2b4d3f24b4c8e4e0f"
  }
  ```

### Analytics Service

- `GET /analytics`: Get analytics data (admin only).

### Notification Service

- Runs in the background and does not expose endpoints.

## Usage Examples

### Registering a New User

```bash
curl -X POST https://appsxyzabc.com/signup \
  -H "Content-Type: application/json" \
  -d '{"username": "john_doe", "password": "secure_password"}'
```

### Logging In

```bash
curl -X POST https://appsxyzabc.com/login \
  -H "Content-Type: application/json" \
  -d '{"username": "john_doe", "password": "secure_password"}'
```

**Response**:

```json
{
  "access_token": "jwt_token_here",
  "token_type": "bearer",
  "role": "user"
}
```

### Applying for Finance

```bash
curl -X POST https://appsxyzabc.com/apply \
  -H "Authorization: Bearer jwt_token_here" \
  -H "Content-Type: application/json" \
  -d '{
    "loan_types": ["personal"],
    "amount": 15000,
    "purpose": "Car purchase"
  }'
```

### Checking Application Status

```bash
curl -X GET https://appsxyzabc.com/status \
  -H "Authorization: Bearer jwt_token_here"
```

### Fetching Analytics Data (Admin)

```bash
curl -X GET https://appsxyzabc.com/analytics \
  -H "Authorization: Bearer admin_jwt_token_here"
```

## Summary

FinApp demonstrates a robust microservices architecture suitable for scalable financial applications. By leveraging RabbitMQ and MongoDB, the system ensures efficient communication and reliable data storage. Deployment is streamlined using Docker and Kubernetes, providing scalability and resilience. Continuous Integration and Deployment are automated using GitHub Actions, ensuring consistent and efficient delivery of updates.

- **RabbitMQ** enables asynchronous messaging between services, decoupling them and enhancing scalability.
- **MongoDB** provides a flexible and scalable data storage solution, ideal for the dynamic data models in financial applications.
- **Docker** standardizes the environment, ensuring consistency across different stages.
- **Kubernetes** automates deployment, scaling, and management of containerized applications.
- **Ingress** with Nginx and TLS termination provides secure and efficient routing of external traffic.
- **GitHub Actions** streamlines the CI/CD pipeline, automating the build and deployment process.



**Repository**: [https://github.com/anurag-2911/finappsvc](https://github.com/anurag-2911/finappsvc)

