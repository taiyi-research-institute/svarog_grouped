## 前提

读者需要了解如何调用 gRPC 函数.

## 1. 如何申请 MPC 会话?

⚠ 申请会话一律调用 `MpcSessionManager.SessionConfig`.

### 1.1. 申请 Keygen 会话

请求示例:

```go
request := &SessionConfig{
  SessionType: "keygen",
  KeyQuorum: 3, // 签名时需提供分片数的最小值
  Groups: []*Group{
    &Group{
      GroupName: "ICBC",
      GroupQuorum: 1, // 该组签名时需提供的分片数的最小值
      Members: []*Member{
        &Member{
          MemberName: "ICBC-Wuhan",
          IsAttending: true, // keygen时所有成员都需参与
        },
        &Member{
          MemberName: "ICBC-Chengdu",
          IsAttending: true,
        },
        &Member{
          MemberName: "ICBC-Shanghai",
          IsAttending: true,
        },
      },
    }, // finish group "ICBC"
    &Group{
      GroupName: "BOC",
      GroupQuorum: 1,
      Members: []*Member{
        &Member{
          MemberName: "BOC-Peking",
          IsAttending: true,
        },
        &Member{
          MemberName: "BOC-Jinan",
          IsAttending: true,
        },
        &Member{
          MemberName: "BOC-Lanzhou",
          IsAttending: true,
        },
      }, // finish group "BOCs"
    },
  },
}
```

MpcSessionManager 会校验请求的合理性. 比如门限是否大于成员数.
之后, MpcSessionManager 会补全请求中的 `session_id`, `group_id`, `member_id`, `expire_xxx` 字段, 作为响应返回给调用者.

响应示例如下.

```go
response := &SessionConfig{
  SessionId: "6c7df8b434af4742a2406f88866d8ecd",
  SessionType: "keygen",
  KeyQuorum: 3, // 签名时需提供分片数的最小值
  Groups: []*Group{
    &Group{
      GroupName: "BOC",
      GroupId: 1,
      GroupQuorum: 1,
      Members: []*Member{
        &Member{
          MemberName: "BOC-Jinan",
          MemberId: 1, // 成员按(group_name, member_name)排序后的序号
          IsAttending: true,
        },
        &Member{
          MemberName: "BOC-Lanzhou",
          MemberId: 2,
          IsAttending: true,
        },
        &Member{
          MemberName: "BOC-Peking",
          MemberId: 3,
          IsAttending: true,
        },
      }, // finish group "BOCs"
    },
    &Group{
      GroupName: "ICBC",
      GroupQuorum: 2, // 该组签名时需提供的分片数的最小值
      Members: []*Member{
        &Member{
          MemberName: "ICBC-Chengdu",
          MemberId: 4,
          IsAttending: true,
        },
        &Member{
          MemberName: "ICBC-Shanghai",
          MemberId: 5,
          IsAttending: true,
        },
        &Member{
          MemberName: "ICBC-Wuhan",
          MemberId: 6,
          IsAttending: true, // keygen时所有成员都需参与
        },
      },
    }, // finish group "ICBC"
  },
  // 在北京时间 2023.11.15 06:13:20 之后, 若会话未执行完, 则强制删除会话所有数据.
  ExpireBeforeFinish: 1700000000,
  // 在北京时间 2023.11.16 06:13:20 之后, 若会话已执行完, 则强制删除会话所有数据.
  ExpireAfterFinish: 1700086400,
}
```

### 1.2. 申请 KeygenMnem 会话

KeygenMnem: 把主助记词转化为 MPC 分片.

在常规 Keygen 的基础上, 请求里需要添加如下的组:
  
```go
&Group{
  GroupName: "__mnem__",
  GroupQuorum: 0,
  Members: []*Member{
    // 申请者可以为这个成员定义自己的名称. 请确保不与其他成员重名.
    &Member{
      MemberName: "__mnem__",
      IsAttending: true,
    },
  },
}
```

### 1.3. 申请 Sign 会话

请求示例:

```go
request := &SessionConfig{
  SessionType: "sign",

  // 申请者怎么知道这里填 3 ?
  // 我希望申请者维护 MPC 密钥的结构. 结构就是Member, Group, Quorum.
  KeyQuorum: 3,

  Groups: []*Group{
    &Group{
      GroupName: "ICBC",
      GroupQuorum: 1, // 该组签名时需提供的分片数的最小值
      Members: []*Member{
        &Member{
          MemberName: "ICBC-Wuhan",
          IsAttending: false, // 申请者在自己的业务里收集该字段.
        },
        &Member{
          MemberName: "ICBC-Chengdu",
          IsAttending: true,
        },
        &Member{
          MemberName: "ICBC-Shanghai",
          IsAttending: true,
        },
      },
    }, // finish group "ICBC"
    &Group{
      GroupName: "BOC",
      GroupQuorum: 1,
      Members: []*Member{
        &Member{
          MemberName: "BOC-Peking",
          IsAttending: false,
        },
        &Member{
          MemberName: "BOC-Jinan",
          IsAttending: true,
        },
        &Member{
          MemberName: "BOC-Lanzhou",
          IsAttending: false,
        },
      }, // finish group "BOCs"
    },
  },
  DerivePath: "m/1/2/5",
  ToSign: &TxHashArray{
    Values: [][]byte{
      []byte("Hash of a tx"),
      []byte("Hash of another tx"),
    },
  }
}
```

MpcSessionManager 会校验各组, 以及总的 `IsAttending` 是否满足门限; 还会校验是否提供了 `DerivePath` 和 `ToSign`.

### 1.4. 申请 Reshare 会话

Reshare: 把已有分片转化为新的 MPC 分片.

> 已有分片的数量需满足签名门限.
> 新分片的根公钥与已有分片相同. 也就是说, 全体已有分片与全体新分片是同一个私钥.
> 已有分片之间可以协作 (协作 = 加入同一个 MPC 会话); 新分片之间可以协作; 但已有分片与新分片不能协作.

请求示例:

```go
request := &SessionConfig{
  SessionType: "reshare",

  KeyQuorum: 3,
  ReshareKeyQuorum: 2, // 新密钥的签名门限

  Groups: []*Group{
    &Group{
      GroupName: "HSBC",
      GroupQuorum: 1,
      IsReshare: true,
      // reshare组的成员必须全部出席
      Members: []*Member{
        &Member{
          MemberName: "HSBC-London",
          IsAttending: true,
        },
        &Member{
          MemberName: "HSBC-Hongkong",
          IsAttending: true,
        },
      },
    },
    &Group{
      GroupName: "Chartered",
      GroupQuorum: 1,
      IsReshare: true,
      // reshare组的成员必须全部出席
      Members: []*Member{
        &Member{
          MemberName: "Chartered-London",
          IsAttending: true,
        },
        &Member{
          MemberName: "Chartered-Mumbai",
          IsAttending: true,
        },
      },
    },
    &Group{
      GroupName: "ICBC",
      GroupQuorum: 1, // 该组签名时需提供的分片数的最小值
      Members: []*Member{
        &Member{
          MemberName: "ICBC-Wuhan",
          IsAttending: false, // 申请者在自己的业务里收集该字段.
        },
        &Member{
          MemberName: "ICBC-Chengdu",
          IsAttending: true,
        },
        &Member{
          MemberName: "ICBC-Shanghai",
          IsAttending: true,
        },
      },
    }, // finish group "ICBC"
    &Group{
      GroupName: "BOC",
      GroupQuorum: 1,
      Members: []*Member{
        &Member{
          MemberName: "BOC-Peking",
          IsAttending: false,
        },
        &Member{
          MemberName: "BOC-Jinan",
          IsAttending: true,
        },
        &Member{
          MemberName: "BOC-Lanzhou",
          IsAttending: false,
        },
      }, // finish group "BOCs"
    },
  },
}
```

MpcSessionManager 会校验 `IsAttending == false` 的组及其全体是否满足门限; 而对于 `IsAttending == true` 的组, 则要求全员参与.

响应中的成员按 `(group_is_reshare, group_name, member_name)` 排序.

Reshare 会话成功后, 上游业务记得对 `is_reshare == true` 的组和成员从 1 重新编号.

## 2. 如何加入MPC会话?

调用 `MpcPeer.JoinSession` 加入会话.

⚠ 请求字段 `ses_config` 必须是 `MpcSessionManager.NewSession` 的响应.

调用函数后, 请耐心等待 `SessionResult` 响应.

## 后记

本模块在当前版本对上游模块提出了新的要求: 
在申请 MPC 会话之前, 想办法整理出密钥结构.
密钥结构是 Keygen 时的成员名, 组名, 组内成员, 以及门限; 或者是 Reshare 时拿到新分片的成员名, 组名, 组内成员, 以及门限.
这是因为:

(1) `MpcSessionManager` 不提供密钥结构. 其只是分布式算法的通信枢纽, 只维护临时数据.

(2) `MpcPeer` 不提供密钥结构. 其虽然持有密钥分片文件, 该文件包含完整的密钥结构; 但其不会仅仅为了提供密钥结构就去读取分片文件.

(3) 上游业务是最先知道密钥结构的. 由上游业务来维护, 便于保持业务的一致性. 否则, MpcSessionManager 或者 MpcPeer 再维护一份, 是不是还要提供增删改查接口?

