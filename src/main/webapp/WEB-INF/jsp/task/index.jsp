<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en" class="no-js">


<head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>定时任务管理</title>
    <jsp:include page="/static/style.jsp"/>
</head>

<body class="gray-bg">
<div class="wrapper wrapper-content  animated fadeInRight">
    <div class="row">
        <div class="col-sm-12">
            <div class="ibox ">
                <div class="ibox-content">
                    <div class="row row-lg">
                        <div class="col-sm-12">
                            <!-- Example Card View -->
                            <div class="example-wrap">
                                <div class="demoTable">
                                    <div class="layui-inline">
                                        <input class="layui-input" name="" id="taskTitle" autocomplete="off"
                                               placeholder="任务标题">
                                    </div>
                                    <div class="layui-inline">
                                        <input class="layui-input" name="" id="taskDesc" autocomplete="off"
                                               placeholder="任务内容">
                                    </div>
                                    <button class="layui-btn" data-type="reload">查询</button>
                                </div>
                                <div class="example">
                                    <table class="layui-hide" lay-filter="mainTable" id="table"></table>
                                </div>
                            </div>
                            <!-- End Example Card View -->
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<script src="${home}/static/js/layui.js" charset="utf-8"></script>
<script src="${home}/static/js/jquery-1.9.1.min.js" charset="utf-8"></script>
<script>
    $(document).ready(function () {
        //初始化表格,动态从服务器加载数据
        layui.use('table', function () {
            var table = layui.table;
            table.render({
                elem: '#table'
                , url: '${home}/sysTask/list'
                , request: {
                    pageName: 'pageNumber' //页码的参数名称，默认：page
                    , limitName: 'pageSize' //每页数据量的参数名，默认：limit
                }
                , id: 'table'
                , height: 'full-100'
                , autoSort: false
                , where: {sortName: 'title', sortOrder: 'DESC'}
                , toolbar: '#toolbarDemo'
                , defaultToolbar: ['filter', 'exports']
                , cols: [[ //标题栏
                    {type: 'radio', fixed: 'left'},
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                       /* sort: true,*/
                        hide: true
                    }, {
                        title: '任务标题',
                        field: 'taskTitle',
                        fixed: 'left',
                        width: 180
                    },  {
                        title: "cron表达式",
                        field: "cronExpression",
                        width: 180,
                    }, {
                        title: "执行类型",
                        field: "taskType",
                        width: 90,
                        templet: function (d) {
                            if (d.taskType === 1)
                                return '<span >sql</span>'
                            else if (d.taskType === 2)
                                return '<span >代码方法</span>'
                            else
                                return '<span ></span>'
                        }
                    }, {
                        title: "执行内容",
                        field: "executeContent",
                        width: 120,
                    }, {
                        title: "是否启用",
                        field: "state",
                        templet: function (d) {
                            if (d.state == '1')
                                return '<span class="label label-primary">启用中</span>'
                            else
                                return '<span class="label label-danger">已暂停</span>'
                        },
                        width: 90
                    }, /*{
                        title: "创建时间",
                        field: "createTime",
                        sort: true
                        , templet: function (d) {
                            return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                        }
                    },*/ {
                        title: "创建时间",
                        field: "createDate",
                        width: 180
                    }, {
                        title: "备注",
                        field: "remark"
                    }
                    , {
                        title: "自定义参数",
                        field: "params"
                    }
                ]]
                , parseData: function (res) { //res 即为原始返回的数据
                    return {
                        "code": 0, //解析接口状态
                        "data": res.records, //解析数据列表
                        "count": res.total,

                    };
                }
                , page: true
                , limits: [5, 10, 15, 20, 50, 100]
                , limit: 10 //每页默认显示的数量
            });

            table.on('toolbar(mainTable)', function (obj) {
                var checkStatus = table.checkStatus(obj.config.id);
                switch (obj.event) {
                    case 'add':
                        add();
                        break;
                    case 'delete':
                        var data = checkStatus.data
                        if (data.length == 0) {
                            layer.msg('请最少选择一条数据');
                            return false;
                        }
                        del(data[0].id);
                        break;
                    case 'update':
                        var data = checkStatus.data
                        if (data.length == 0) {
                            layer.msg('请最少选择一条数据');
                            return false;
                        }
                        edit(data[0].id);
                        break;
                    case 'execute':
                        var data = checkStatus.data
                        if (data.length == 0) {
                            layer.msg('请最少选择一条数据');
                            return false;
                        }
                        execute(data[0].id);
                        break;
                }
                ;
            });

            //排序重载
            table.on('sort(mainTable)', function (obj) {
                table.reload('table', {initSort: obj, where: {sortName: obj.title}});
            });

            var $ = layui.$, active = {
                reload: function () {
                    var taskTitle = $('#taskTitle');
                    var taskDesc = $('#taskDesc');
                    table.reload('table', {
                        page: {
                            curr: 1 //重新从第 1 页开始
                        }
                        , where: {
                            title: taskTitle.val(),
                            content: taskDesc.val()
                        }
                    }, 'data');
                }
            };

            $('.demoTable .layui-btn').on('click', function () {
                var type = $(this).data('type');
                active[type] ? active[type].call(this) : '';
            });
        });
    });

    function edit(id) {
        layer.open({
            id: 'showLayer',
            type: 2,
            title: '任务修改',
            shadeClose: true,
            shade: false,
            area: ['893px', '500px'],
            content: '${home}/sysTask/edit/' + id,
            end: function (index) {
                tableReload();
            }
        });
    }

    function add() {
        layer.open({
            id: 'showLayer',
            type: 2,
            title: '任务添加',
            shadeClose: true,
            shade: false,
            area: ['893px', '500px'],
            content: '${home}/sysTask/add',
            end: function (index) {
                tableReload();
            }
        });
    }

    function del(id) {
        layer.confirm('确定删除吗?', {icon: 3, title: '提示'}, function (index) {
            $.ajax({
                type: "POST",
                dataType: "json",
                url: "${home}/sysTask/delete/" + id ,
                success: function (result) {
                    layer.msg(result.msg, {time: 2000}, function () {
                        tableReload();
                        if (result.ok) {
                            parent.layer.close(index);
                        }
                    });
                }
            });
        });
    }

    function execute(id) {
        layer.confirm('确定要立刻执行一次此任务吗?', {icon: 3, title: '提示'}, function (index) {
            parent.layer.close(index);
            $.ajax({
                type: "POST",
                dataType: "json",
                url: "${home}/sysTask/execute/" + id ,
                success: function (result) {
                    layer.msg(result.msg, {time: 3000});
                }
            });
        })
    }


    function tableReload() {
        layui.use('table', function () {
            var table = layui.table;
            table.reload('table');
        })
    }

    $('input').bind('keyup', function (event) {
        if (event.keyCode == "13") {
            //回车执行查询
            $('[data-type="reload"]').trigger('click')
        }
    });
</script>

<script type="text/html" id="toolbarDemo">
    <div class="layui-btn-container">
            <button class="layui-btn layui-btn-sm" lay-event="add">添加</button>
            <button class="layui-btn layui-btn-sm"  style="background-color: red !important;border-color: rgb(199,0,0);color:white !important;" lay-event="delete">删除</button>
            <button class="layui-btn layui-btn-sm" lay-event="update">编辑</button>
            <button class="layui-btn layui-btn-sm" lay-event="execute">立即执行一次</button>
    </div>
</script>


<style>

</style>
</body>

</html>
