<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en" class="no-js">


<head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">


    <title>用户管理页面</title>
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

                                        <div class="layui-input-inline" style="margin-top: 10px">
                                            <label>时间选择</label>
                                            <div class="layui-input-inline">

                                                <input type="text" id="date" placeholder="请选择时间" autocomplete="off"
                                                       class="layui-input">
                                            </div>

                                        </div>
                                        <div class="layui-input-inline" style="margin-left: 10px;margin-top: 10px">
                                            <label>按用户类型</label>
                                            <div class="layui-input-inline ">
                                                <select class="selectpicker " data-width="100px"  id="type" value="0">
                                                    <option value="">全部</option>
                                                    <option value="0" selected>客户</option>
                                                    <option value="1">管理员</option>
                                                </select>
                                            </div>

                                        </div>
                                        <div class="layui-input-inline" style="margin-left: 10px;margin-top: 10px">
                                            <label>按用户</label>
                                            <div class="layui-input-inline ">


                                                <select class="selectpicker " data-live-search-placeholder="请输入" multiple
                                                        data-live-search="true" id="user" title="请选择用户"
                                                        data-divider="true"
                                                        data-actions-box="true" data-size="5">

                                                </select>
                                            </div>

                                        </div>


                                        <div class="layui-input-inline" style="margin-left: 10px;margin-top: 10px">

                                            <button class="layui-btn  layui-btn-normal" data-type="reload">查询</button>
                                            <button class="layui-btn  layui-btn" onclick="reset()">重置</button>
                                        </div>
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
<script src="${home}/static/js/popper.min.js"></script>
<script src="${home}/static/js/bootstrap.js"></script>
<%--<script src="${home}/static/js/bootstrap-dropdown.js"></script>--%>
<script src="${home}/static/js/bootstrap-select.js"></script>
<script src="${home}/static/js/defaults-zh_CN.min.js"></script>
<script>
    $(document).ready(function () {
        let isAdmin = $('#type').val()
        //初始化表格,动态从服务器加载数据
        layui.use('table', function () {
            var table = layui.table;
            table.render({
                elem: '#table'
                , url: '${home}/activeUser/list'
                , request: {
                    pageName: 'pageNumber' //页码的参数名称，默认：page
                    , limitName: 'pageSize' //每页数据量的参数名，默认：limit
                }
                ,title:'上下分表'
                , id: 'table'
                , height: 'full-100'
                , autoSort: false
                , where: {sortName: 'createDate', sortOrder: 'desc',isAdmin}
                , toolbar: '#toolbarDemo'
                , defaultToolbar: ['filter']
                , cols: [[ //标题栏
                   /* {type: 'radio', fixed: 'left'},*/
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        hide:true
                        /*sort: true*/
                    }, {
                        title: '账号',
                        field: 'username'
                        , align:'center'
                        ,fixed: 'left'
                    }, {
                        title: '用户昵称',
                        field: 'userNickName'
                        , align:'center',
                        fixed: 'left'
                    }, {
                        title: "最后上线时间",
                        field: "createDate",
                        align:'center'

                    }, {
                        title: "最后下注时间",
                        field: "lastLotteryDate",
                        align:'center'

                    }
                    , {
                        title: "用户类型",
                        field: "isAdmin",
                        align:'center',
                        /*sort: true*/
                          templet: function (d) {
                              if(d.isAdmin===0){
                                  return '客户'
                              }

                              return '管理员'

                         }
                    }

                ]]
                , parseData: function (res) { //res 即为原始返回的数据
                    return {
                        "code": 0, //解析接口状态
                        "data": res.records, //解析数据列表
                        "count": res.total,

                    };
                },done:function (res, curr, count){

                }
                , page: true
                , limits: [5, 10, 15, 20, 50, 100]
                ,limit: 10 //每页默认显示的数量
            });

            //排序重载
            table.on('sort(mainTable)', function (obj) {
                table.reload('table', {initSort: obj, where: {sortName: obj.field, sortOrder: obj.type}});
            });
            table.on('toolbar(mainTable)', function (obj) {
                var checkStatus = table.checkStatus(obj.config.id);
                switch (obj.event) {

                }

            });

            var $ = layui.$, active = {
                reload: function () {
                    var date = $('#date').val();
                    var user = $('#user').val();
                    let username = '';
                    let isAdmin = $('#type').val()
                    if (user) {
                        username = user.join(',');
                    }
                    table.reload('table', {
                        page: {
                            curr: 1 //重新从第 1 页开始
                        }
                        , where: {
                            dateStr:date,username,isAdmin
                        }
                    }, 'data');
                }
            };

            $('.demoTable .layui-btn').on('click', function () {
                var type = $(this).data('type');
                active[type] ? active[type].call(this) : '';
            });
        });
        layui.use('laydate', function () {
            var laydate = layui.laydate;
            laydate.render({
                elem: '#date'
                , type: 'date'
                , range: '~'
                , format: 'yyyy-MM-dd'
            });
        })
        function getUserList() {
            let isAdmin = $('#type').val()
            $(user).html('');
            $(user).selectpicker('refresh');
            $.ajax({
                type: "POST",
                dataType: "json",
                url: "${home}/comment/getUserList",
                data: {isAdmin},
                success: function (result) {
                    console.log(result)
                    if (result.length > 0) {
                        for (let i = 0; i < result.length; i++) {
                            let option = '<option  value="' + result[i].value + '">' + result[i].name + '</option>';
                            $(user).append(option)
                            /* $(user).append('<option data-divider="true"></option>')*/
                        }
                    }
                    $(user).selectpicker('refresh');


                }
            });
        }
        getUserList();
        $('#type').on('hidden.bs.select', function (e, clickedIndex, isSelected, previousValue) {
            getUserList()
        })
    });

    function tableReload() {
        layui.use('table', function () {
            var table = layui.table;
            table.reload('table');
        })
    }
    function reset() {
        $('#date').val('');
        $('#user').selectpicker('val','');
        $('#type').selectpicker('val','');


    }
</script>
<script type="text/html" id="toolbarDemo">
    <span>活跃用户表</span>
    <label id="yl" style="display: none"></label>
</script>

</body>

</html>
