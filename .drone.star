def main(ctx):
  ref = ctx.build.ref.split('/')
  tags = []
  if ref[1] == "tags":
    tags = ["latest", ref[2]]
  
  name = "drone-runner-vms"
  pipeline = [
    image(ctx, "amd64", name),
    image(ctx, "arm64", name),
    manifest(ctx, name, tags),
  ]

  return pipeline


def registry():
  return {
    "host": "registry.m4eba.com",
    "namespace": "drone",
    "env": {
      "USER": "m4eba",
      "PASSWORD": {
        "from_secret": "m4eba_registry_password"
      }
    }
  }


def image(ctx, arch, name):
  reg = registry()
  destination = "%s/%s/%s:%s-%s" % (reg["host"],reg["namespace"],name,ctx.build.commit,arch)

  pipeline = {
    "kind": "pipeline",
    "type": "kubernetes",
    "name": "build_%s_%s" % (name,arch),
    "platform": {
      "arch": arch,
    },
    "steps": [
      {
        "name": "build",
        "image": "golang:1.19",
        "commands": [
          'CGO_ENABLED=1 go build -ldflags "-extldflags \"-static\"" -o release/linux/%s/drone-runner-aws-linux-%s' % (arch,arch)
        ]
      },
      {
        "name": "image",
        "image": "gcr.io/kaniko-project/executor:debug",
        "environment": reg["env"],
        "commands": [
            "echo %s %s" % (name, arch),
            '''
              export BASE=`echo -n $USER:$PASSWORD | base64`
              echo -n '{"auths":{"https://%s/v1/":{"auth":"' > /kaniko/.docker/config.json
              echo -n $BASE >> /kaniko/.docker/config.json
              echo -n '"}}}' >> /kaniko/.docker/config.json              
            ''' % reg["host"],
            "cat /kaniko/.docker/config.json",
            '''
            /kaniko/executor \
            --context dir://. \
            --dockerfile ./docker/Dockerfile.linux.%s \
            --use-new-run \
            --snapshot-mode=redo \
            --compressed-caching=false \
            --single-snapshot \
            --destination %s
            ''' % (arch,destination)
        ]
      }
    ]
  }
  
  
  pipeline["node_selector"] = {
    "cpuworker": "true",
    "kubernetes.io/arch": arch
  }
  
  pipeline["tolerations"] = [
    {
      "key": "cputasks",
      "operator": "Exists",
      "effect": "NoSchedule",
    }
  ]
  return pipeline

def manifest(ctx,name,tags):
  reg = registry()
  template = '%s/%s/%s:%s-ARCH' % (reg["host"],reg["namespace"],name,ctx.build.commit)
  target = '%s/%s/%s:%s' % (reg["host"],reg["namespace"],name,ctx.build.commit)
  tags_string = ''
  if len(tags)>0:
    tags_string = '--tags '+','.join(tags)
  
  return {
    "kind": "pipeline",
    "type": "kubernetes",
    "name": "manifest_%s" % name,
    "depends_on": [
      "build_%s_arm64" % name,
      "build_%s_amd64" % name,
    ],
    "steps": [
      {
          "name": "manifest tool",
          "image": "mplatform/manifest-tool:alpine",
          "environment": reg["env"],
          "commands": [
              '''
                manifest-tool \
                --username=$USER\
                --password=$PASSWORD\
                push from-args\
                --platforms linux/amd64,linux/arm64\
                --template %s\
                --target %s\
                %s
              ''' % (template,target,tags_string)
          ]
        }
    ]
  }