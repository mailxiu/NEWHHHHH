<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en" class="no-js">


<head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">


    <title>定时任务执行日志</title>
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

                                        <div class="layui-input-inline">
                                            <input type="text" id="content"  placeholder="请输入任务标题或内容" autocomplete="off" class="layui-input">
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
                , url: '${home}/sysTaskLog/list'
                , request: {
                    pageName: 'pageNumber' //页码的参数名称，默认：page
                    , limitName: 'pageSize' //每页数据量的参数名，默认：limit
                }
                , id: 'table'
                , height: 'full-100'
                , autoSort: false
                , where: {sortName: 'createTime', sortOrder: 'desc'}
                , toolbar: '#toolbarDemo'
                , defaultToolbar: ['filter', 'exports']
                , cols: [[ //标题栏
                    {type: 'radio', fixed: 'left'},
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        /*sort: true*/
                    }, {
                        title: '任务标题',
                        field: 'title',
                    }, {
                        title: '任务内容',
                        field: 'taskContent',
                    }, {
                        title: "执行状态",
                        field: "isSuccess",
                        templet: function (d) {
                            if (d.isSuccess === 0)
                                return '<span >失败</span>'
                            else if (d.isSuccess === 1)
                                return '<span >成功</span>'
                            else
                                return '<span ></span>'
                        }
                    }, {
                        title: "执行结果",
                        field: "taskResult"
                    }, {
                        title: "执行时间",
                        field: "createDate",
                        /*sort: true*/
                       /* , templet: function (d) {
                            return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                        }*/
                    }
                    , {
                        title: "结束时间",
                        field: "endDate",
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
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
                            content: content.val()
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


    function tableReload() {
        layui.use('table', function () {
            var table = layui.table;
            table.reload('table');
        })
    }

</script>


</body>

</html>
