# 用户模块 API 接口文档说明

本目录包含安全电子商务系统（用户模块）的 OpenAPI 3.0 契约文件 `openapi.yaml`。

## 一、 如何导入与查看文档？

你可以使用 **Apifox**、**Postman** 或在线 **Swagger Editor** 来查看和调试本接口。

1. **使用 Apifox / Postman**：
   - 打开软件，选择“导入数据”。
   - 选择“OpenAPI / Swagger”格式。
   - 将本目录下的 `openapi.yaml` 文件拖入，或直接粘贴文件内容。
   - 点击导入即可生成可视化的接口文档。
2. **使用 Swagger Editor (在线)**：
   - 打开 [https://editor.swagger.io/](https://editor.swagger.io/)。
   - 将 `openapi.yaml` 的内容直接粘贴到左侧代码框中，右侧会自动生成文档。

## 二、 如何测试受保护接口（鉴权说明）

1. 在文档中找到并调用 **`POST /api/auth/login`**（用户登录）接口。
2. 在请求体中输入正确的账号密码，点击发送。
3. 在返回的 JSON 响应体中，复制 `accessToken` 的值。
4. 点击 Apifox/Postman 界面上的 **Authorization（鉴权）** 标签页（或右上角的环境变量配置处）。
5. 类型选择 **Bearer Token**（或 Bearer Auth），将复制的 Token 粘贴进去。
6. 现在你可以直接测试 `/api/users/me`、`/api/auth/verify` 等需要鉴权的接口了。

## 三、 接口约定与错误码说明

1. **请求体格式**：除 GET 和退出接口外，所有接口要求 `Content-Type: application/json`。
2. **错误响应**：系统采用统一的封闭错误码（见 `src/user/errors.py`）。所有错误响应格式固定为：
   ```json
   {
     "code": "ERROR_CODE",
     "message": "错误描述",
     "traceId": "用于排查的追踪编号",
     "details": [{"field": "字段名", "reason": "错误原因"}]
   }