<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html  lang="en" class="no-js">

<head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">


    <title> - 表单验证 jQuery Validation</title>
    <meta name="keywords" content="">
    <meta name="description" content="">
    <jsp:include page="/static/style.jsp"/>

    <script src="${home}/static/js/layui.js" charset="utf-8"></script>
    <script src="${home}/static/js/jquery-1.9.1.min.js" charset="utf-8"></script>
    <script src="${home}/static/js/jquery.validate.min.js" charset="utf-8"></script>


</head>

<body class="gray-bg">
<div class="wrapper wrapper-content animated fadeInRight">
    <div class="row">
        <div class="col-sm-12">
            <div class="ibox float-e-margins">
                <div class="ibox-content">
                    <form class="form-horizontal m-t" id="frm" method="post" action="${home}/sysTask/edit.json">
                        <input type="hidden" id="id" name="id" value="${task.id}">

                        <div class="form-group">
                            <label class="col-sm-3 control-label label-required-next">任务名称：</label>
                            <div class="col-sm-8">
                                <input id="taskTitle" name="taskTitle" class="form-control" type="text" value="${task.taskTitle}">
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="col-sm-3 control-label label-required-next">任务类型：</label>
                            <div class="col-sm-8">
                                <select name="taskType" class="form-control">
                                    <option value="2" ${task.taskType == 2 ?'selected="selected"':''}>代码方法</option>
                                    <option value="1" ${task.taskType == 1 ?'selected="selected"':''}>sql</option>
                                </select>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label label-required-next">执行内容：</label>
                            <div class="col-sm-8">
                                <textarea id="executeContent" name="executeContent" class="form-control" type="text" value="${task.executeContent}" rows="4"></textarea>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label label-required-next">cron表达式(最多6个参数)：</label>
                            <div class="col-sm-8">
                                <input id="cronExpression" name="cronExpression" class="form-control" type="text" value="${task.cronExpression}">
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">是否启用：</label>
                            <div class="col-sm-8">
                                <select name="state" class="form-control">
                                    <option value="1" ${task.state == 1 ?'selected="selected"':''}>启用</option>
                                    <option value="0" ${task.state == null || task.state == 0 ?'selected="selected"':''}>不启用</option>
                                </select>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">自定义参数：</label>
                            <div class="col-sm-8">
                                <input id="params" name="params" class="form-control" type="text" value="${task.params}">
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">备注：</label>
                            <div class="col-sm-8">
                                <input id="taskRemark" name="taskRemark" class="form-control" type="text" value="${task.taskRemark}">
                            </div>
                        </div>
                        <div class="form-group">
                            <div class="col-sm-8 col-sm-offset-3">
                                <button class="btn layui-btn" type="submit">提交</button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

</div>
<script type="text/javascript">
    $(document).ready(function () {
        $("#executeContent").text(`${task.executeContent}`)
        $("#frm").validate({
            rules: {
                name: {
                    required: true,
                    minlength: 1,
                    maxlength: 20
                },
                sourceKey: {
                    required: true,
                    minlength: 4,
                    maxlength: 40
                },
                type: {
                    required: true
                },
                level: {
                    required: true,
                    number: true
                },
                sort: {
                    number: true,
                    required: true
                },
                icon: {
                    maxlength: 40
                },
                isHide: {
                    required: true
                },
            },
            messages: {},
            submitHandler: function (form) {
                $.ajax({
                    type: "POST",
                    dataType: "json",
                    url: "${home}/sysTask/edit",
                    data: $(form).serialize(),
                    success: function (result) {
                        layer.msg(result.msg, {time: 2000}, function () {
                            var index = parent.layer.getFrameIndex(window.name); //先得到当前iframe层的索引
                            if (result.code==200) {
                                parent.layer.close(index);
                            }
                        });
                    }
                });
            }
        });
    });
</script>

</body>

</html>
