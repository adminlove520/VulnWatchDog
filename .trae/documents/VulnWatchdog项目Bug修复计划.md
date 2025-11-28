# VulnWatchdog项目Bug修复计划

## 1. 修复FastGPT返回内容解析问题
- **问题**：FastGPT返回的内容包含```json和```标记，导致JSON解析失败
- **解决方案**：修改`_call_fastgpt`函数，在解析JSON之前移除这些标记
- **文件**：`libs/gpt_utils.py`

## 2. 修复任务成功但缺少必要字段问题
- **问题**：GPT返回结果缺少必要字段，导致任务成功但无法生成完整报告
- **解决方案**：
  - 检查`gpt_queue.py`中的必要字段列表
  - 确保GPT提示词要求返回所有必要字段
  - 在`_handle_success`函数中添加字段检查和默认值处理
- **文件**：`libs/gpt_queue.py`

## 3. 修复资源警告问题
- **问题**：`webhook.py`中打开文件后没有关闭，导致资源泄漏
- **解决方案**：使用`with`语句打开文件，确保文件能正确关闭
- **文件**：`libs/webhook.py`

## 4. 移除多余逻辑，只用CVE年份范围
- **问题**：代码中存在多余的逻辑，需要只用CVE年份范围
- **解决方案**：检查`main.py`中的相关逻辑，移除多余的代码
- **文件**：`main.py`

## 5. 日志中显示GPT_PROVIDER
- **问题**：日志中运行参数没有显示GPT_PROVIDER
- **解决方案**：修改`main.py`中的日志记录，添加GPT_PROVIDER信息
- **文件**：`main.py`

## 6. 统一Gemini模型为gemini-2.0-flash
- **问题**：Gemini模型名称不统一
- **解决方案**：修改`config.py`中的默认Gemini模型名称
- **文件**：`config.py`

## 7. 实施步骤
1. 修复FastGPT返回内容解析问题
2. 修复资源警告问题
3. 移除多余逻辑
4. 更新日志记录
5. 统一Gemini模型名称
6. 修复缺少必要字段问题
7. 测试所有功能，确保正常运行

## 8. 预期效果
- FastGPT返回的内容能正确解析为JSON格式
- 不再出现资源警告
- 代码逻辑更简洁，只用CVE年份范围
- 日志中能显示GPT_PROVIDER信息
- Gemini模型统一为gemini-2.0-flash
- GPT返回结果包含所有必要字段，能生成完整报告