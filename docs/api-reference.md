# API Reference

This document provides a reference for the CipherTrust Manager REST API endpoints used by the ThalesGroup CipherTrust Ansible Collection.

## Authentication

### Login

**Endpoint:** `POST /api/v1/auth/login`

**Request:**
```json
{
  "username": "admin",
  "password": "password"
}
```

**Response:**
```json
{
  "id": "token-id",
  "token": "token-value",
  "user": {
    "id": "user-id",
    "name": "admin",
    "email": "admin@example.com"
  }
}
```

## Cluster Management

### Get Cluster Status

**Endpoint:** `GET /api/v1/cluster/status`

**Response:**
```json
{
  "cluster_id": "cluster-id",
  "nodes": [
    {
      "id": "node-id",
      "ip": "10.0.0.1",
      "status": "active"
    }
  ]
}
```

## Key Management

### Create Key

**Endpoint:** `POST /api/v1/keys`

**Request:**
```json
{
  "name": "my-key",
  "key_type": "symmetric",
  "algorithm": "AES",
  "key_size": 256
}
```

**Response:**
```json
{
  "id": "key-id",
  "name": "my-key",
  "key_type": "symmetric",
  "algorithm": "AES",
  "key_size": 256
}
```

### Get Key

**Endpoint:** `GET /api/v1/keys/{key_id}`

**Response:**
```json
{
  "id": "key-id",
  "name": "my-key",
  "key_type": "symmetric",
  "algorithm": "AES",
  "key_size": 256
}
```

## User Management

### Create User

**Endpoint:** `POST /api/v1/users`

**Request:**
```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "password",
  "role": "admin"
}
```

**Response:**
```json
{
  "id": "user-id",
  "username": "newuser",
  "email": "newuser@example.com",
  "role": "admin"
}
```

### Get User

**Endpoint:** `GET /api/v1/users/{user_id}`

**Response:**
```json
{
  "id": "user-id",
  "username": "newuser",
  "email": "newuser@example.com",
  "role": "admin"
}
```

## Group Management

### Create Group

**Endpoint:** `POST /api/v1/groups`

**Request:**
```json
{
  "name": "my-group",
  "description": "My group"
}
```

**Response:**
```json
{
  "id": "group-id",
  "name": "my-group",
  "description": "My group"
}
```

### Get Group

**Endpoint:** `GET /api/v1/groups/{group_id}`

**Response:**
```json
{
  "id": "group-id",
  "name": "my-group",
  "description": "My group"
}
```

## Interface Management

### Create Interface

**Endpoint:** `POST /api/v1/interfaces`

**Request:**
```json
{
  "name": "my-interface",
  "ip": "10.0.0.1",
  "netmask": "255.255.255.0",
  "gateway": "10.0.0.254"
}
```

**Response:**
```json
{
  "id": "interface-id",
  "name": "my-interface",
  "ip": "10.0.0.1",
  "netmask": "255.255.255.0",
  "gateway": "10.0.0.254"
}
```

### Get Interface

**Endpoint:** `GET /api/v1/interfaces/{interface_id}`

**Response:**
```json
{
  "id": "interface-id",
  "name": "my-interface",
  "ip": "10.0.0.1",
  "netmask": "255.255.255.0",
  "gateway": "10.0.0.254"
}
```

## License Management

### Get License

**Endpoint:** `GET /api/v1/licenses`

**Response:**
```json
{
  "licenses": [
    {
      "id": "license-id",
      "name": "enterprise",
      "expires": "2023-12-31"
    }
  ]
}
```

## DPG Management

### Create DPG Policy

**Endpoint:** `POST /api/v1/dpg/policies`

**Request:**
```json
{
  "name": "my-policy",
  "description": "My DPG policy"
}
```

**Response:**
```json
{
  "id": "policy-id",
  "name": "my-policy",
  "description": "My DPG policy"
}
```

### Get DPG Policy

**Endpoint:** `GET /api/v1/dpg/policies/{policy_id}`

**Response:**
```json
{
  "id": "policy-id",
  "name": "my-policy",
  "description": "My DPG policy"
}
```

## CTE Management

### Create CTE Client

**Endpoint:** `POST /api/v1/cte/clients`

**Request:**
```json
{
  "name": "my-client",
  "description": "My CTE client"
}
```

**Response:**
```json
{
  "id": "client-id",
  "name": "my-client",
  "description": "My CTE client"
}
```

### Get CTE Client

**Endpoint:** `GET /api/v1/cte/clients/{client_id}`

**Response:**
```json
{
  "id": "client-id",
  "name": "my-client",
  "description": "My CTE client"
}
```

## Error Codes

| Code | Message | Description |
|------|---------|-------------|
| 400 | Bad Request | Invalid request parameters |
| 401 | Unauthorized | Authentication failed |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 500 | Internal Server Error | Server error |

## Rate Limiting

The API has rate limiting:
- Maximum 100 requests per minute
- Exceeding rate limit returns 429 status code

## Pagination

List endpoints support pagination:
- `?page=1` - Page number
- `?page_size=100` - Items per page

## Filtering

List endpoints support filtering:
- `?name=my-name` - Filter by name
- `?type=my-type` - Filter by type

## Sorting

List endpoints support sorting:
- `?sort=name` - Sort by name
- `?sort=-name` - Sort by name descending
