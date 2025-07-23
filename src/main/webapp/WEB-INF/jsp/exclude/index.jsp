<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en" class="no-js">


<head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">


    <title>暖场账号配置页面</title>
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
                                <div class="demoTable" style="margin-left: 50px">
                                    <%--<div class="layui-inline">--%>
                                    <%--<input class="layui-input" name="" id="categoryCode" autocomplete="off"--%>
                                    <%--placeholder="字典目录编码">--%>
                                    <%--</div>--%>
                                    <%--<div class="layui-inline">--%>
                                    <%--<input class="layui-input" name="" id="categoryValue" autocomplete="off"--%>
                                    <%--placeholder="字典项值">--%>
                                    <%--</div>--%>

                                       <%-- <div class="layui-input-inline">
                                            <input type="text" id="content"  placeholder="请输入帐号或昵称" autocomplete="off" class="layui-input">
                                        </div>

                                    <button class="layui-btn" data-type="reload">查询</button>--%>
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
                , url: '${home}/exclude/list'
                , request: {
                    pageName: 'pageNumber' //页码的参数名称，默认：page
                    , limitName: 'pageSize' //每页数据量的参数名，默认：limit
                }
                , id: 'table'
                , height: 'full-100'
                , autoSort: false
                , where: {sortName: 'createDate', sortOrder: 'desc'}
                , toolbar: '#toolbarDemo'
                , defaultToolbar: ['filter']
                ,align:'center'
                , cols: [[ //标题栏
                    {type: 'radio', fixed: 'left'},
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        hide:true
                        /*sort: true*/
                    }, {
                        title: '暖场账号',
                        field: 'userName',
                        align:'center'
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
                ,limit: 10 //每页默认显示的数量
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

                }

            });

            //排序重载
            table.on('sort(mainTable)', function (obj) {
                table.reload('table', {initSort: obj, where: {sortName: obj.field, sortOrder: obj.type}});
            });

            var $ = layui.$, active = {
                reload: function () {
                    var content = $('#content');

                    table.reload('table', {
                        page: {
                            curr: 1 //重新从第 1 页开始
                        }
                        , where: {
                            username: content.val()
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
            title: '修改',
            shadeClose: true,
            shade: false,
            area: ['500px', '500px'],
            content: '${home}/exclude/form?id='+id,
            end: function (index) {
                tableReload();
            }
        });
    }

    function add() {
        layer.open({
            id: 'showLayer',
            type: 2,
            title: '添加',
            shadeClose: true,
            shade: false,
            area: ['400px', '300px'],
            content: '${home}/exclude/form',
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
                url: "${home}/exclude/delete/" + id ,
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




    function tableReload() {
        layui.use('table', function () {
            var table = layui.table;
            table.reload('table');
        })
    }

</script>
<script type="text/html" id="toolbarDemo">
    <div class="layui-btn-container">
        <button class="layui-btn layui-btn-normal" lay-event="add">添加</button>
        <button class="layui-btn layui-btn-warm" lay-event="update">编辑</button>
        <button class="layui-btn layui-btn-danger" lay-event="delete">删除</button>
    </div>
</script>

</body>

</html>
