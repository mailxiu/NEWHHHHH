<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en" class="no-js" style="height: 100%;min-height: 1080px;width: 100%;min-width: 720px;">


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
                                        <div class="layui-input-inline" style="margin-top: 10px">
                                        <div class="layui-input-inline">
                                            <input type="text" id="content"  placeholder="请输入帐号或昵称" autocomplete="off" class="layui-input">
                                        </div>
                                        </div>
                                        <div class="layui-input-inline" style="margin-left: 10px;margin-top: 10px">
                                            <label>积分是否大于0</label>
                                            <div class="layui-input-inline ">
                                                <select class="selectpicker " data-width="100px"  id="jifen">
                                                    <option value="">全部</option>
                                                    <option value="1">大于0</option>
                                                    <option value="0">小于0</option>
                                                </select>
                                            </div>

                                        </div>
                                        <div class="layui-input-inline" style="margin-left: 10px;margin-top: 10px">
                                            <label>在线状态</label>
                                            <div class="layui-input-inline ">
                                                <select class="selectpicker " data-width="100px"  id="status">
                                                    <option value="">全部</option>
                                                    <option value="1">在线</option>
                                                    <option value="0">离线</option>
                                                </select>
                                            </div>

                                        </div>
                                    <button class="layui-btn  layui-btn-normal" data-type="reload">查询</button>
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
<script src="${home}/static/js/xadmin.js" charset="utf-8"></script>
<script src="${home}/static/js/popper.min.js"></script>
<script src="${home}/static/js/bootstrap.js"></script>
<%--<script src="${home}/static/js/bootstrap-dropdown.js"></script>--%>
<script src="${home}/static/js/bootstrap-select.js"></script>
<script src="${home}/static/js/defaults-zh_CN.min.js"></script>
<script>
    $(document).ready(function () {
        let status = '${status}'
        if(status){
            $('#status').selectpicker('val',status);
        }
        //初始化表格,动态从服务器加载数据
        layui.use('table', function () {
            var table = layui.table;
            table.render({
                elem: '#table'
                , url: '${home}/sysUser/list'
                , request: {
                    pageName: 'pageNumber' //页码的参数名称，默认：page
                    , limitName: 'pageSize' //每页数据量的参数名，默认：limit
                }
                , id: 'table'
                , height: 'full-100'
                , autoSort: false
                , where: {sortName: 'createDate', sortOrder: 'desc',status}
                , toolbar: '#toolbarDemo'
                , defaultToolbar: ['filter']
                ,align:'center'
                , cols: [[ //标题栏
                    {type: 'radio', fixed: 'left',title:'选择'},
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        hide:true
                        /*sort: true*/
                    }, {
                        title: '账号',
                        field: 'username',
                        fixed: 'left',
                        align:'center'
                    }, {
                        title: '昵称',
                        field: 'nickName',
                        align:'center'
                    }, {
                        title: "积分",
                        field: "money",
                        align:'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "是否管理员",
                        align:'center',
                        field: "isAdim"
                        /*sort: true*/
                         , templet: function (d) {
                             if(d.isAdmin){
                                 return '管理员'
                             }else {
                                 return '客户'
                             }

                         }
                    }, {
                        title: "是否直播员",
                        align:'center',
                        field: "isLive"
                        /*sort: true*/
                         , templet: function (d) {
                             if(d.isLive){
                                 return '是'
                             }else {
                                 return '不是'
                             }

                         }
                    }, {
                        title: "在线状态",
                        align:'center',
                        field: "status"
                        /*sort: true*/
                        , templet: function (d) {
                            if(d.status){
                                return '在线'
                            }else {
                                return '离线'
                            }

                        }
                    }
                    , {
                        title: "创建时间",
                        field: "createDate",
                        /*sort: true*/
                       /* , templet: function (d) {
                            return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                        }*/
                    },
                    {   title: '操作',
                        fixed: 'right',
                        align:'center',
                        align:'center',
                        field: 'id',
                        toolbar: '#barDemo',
                        minWidth: 200
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
                    case 'detail':
                        layer.msg('detail');
                        break;
                    case 'plus':
                        var data = checkStatus.data
                        layer.msg('plus');
                        if (data.length == 0) {
                            layer.msg('请最少选择一条数据');
                            return false;
                        }
                        break;
                    case 'reduce':
                        layer.msg('reduce');
                        var data = checkStatus.data
                        if (data.length == 0) {
                            layer.msg('请最少选择一条数据');
                            return false;
                        }

                        break;
                    case 'lotteryDetail':
                        layer.msg('lotteryDetail');
                        var data = checkStatus.data
                        if (data.length == 0) {

                            return false;
                        }

                        break;
                }

            });
            table.on('tool(mainTable)', function (obj) {
                console.log(obj)

                switch (obj.event) {
                    case 'detail':
                        var data = obj.data;
                        userRechargeDetail(data.username)
                        break;
                    case 'plus':
                        var data = obj.data
                        plus(data.id,data.username)
                        break;
                    case 'reduce':
                        var data = obj.data
                        reduce(data.id,data.username)

                        break;
                    case 'lotteryDetail':
                       // layer.msg('lotteryDetail');
                        var data = obj.data
                        /*xadmin.add_tab('用户投注列表','${home}'+'/userLottery/index?username='+data.username)
                        if (data.length == 0) {

                            return false;
                        }*/
                        userLotteryDetail(data.username)
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
                    var dateStr = $('#date').val();
                    var status = $('#status').val();
                    var jifen = $('#jifen').val();
                    table.reload('table', {
                        page: {
                            curr: 1 //重新从第 1 页开始
                        }
                        , where: {
                            username: content.val(),dateStr,status,jifen
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
    });

    function edit(id) {
        let width = $('html').width();
        let height = $('html').height();
        width = 480;
        height = 500;
        layer.open({
            id: 'showLayer',
            type: 2,
            title: '修改用户',
            shadeClose: true,
            shade: false,
            area: [width+'px', height+'px'],
            content: '${home}/sysUser/edit/' + id,
            end: function (index) {
                tableReload();
            }
        });
    }

    function userLotteryDetail(username) {
        let width = $('html').width();
        let height = $('html').height();
        width = width*0.95;
        height = height*0.98;
        layer.open({
            id: 'showLayer',
            type: 2,
            title: '用户投注明细',
            shadeClose: true,
            shade: false,
            area: [width+'px', height+'px'],
            content: '${home}'+'/userLottery/index?username='+username,
            end: function (index) {
                //tableReload();
            }
        });
    }
    function userRechargeDetail(username) {
        let width = $('html').width();
        let height = $('html').height();
        width = width*0.95;
        height = height*0.98;
        layer.open({
            id: 'showLayer',
            type: 2,
            title: '用户上下分明细',
            shadeClose: true,
            shade: false,
            area: [width+'px', height+'px'],
            content: '${home}'+'/recharge/index?username='+username,
            end: function (index) {
                //tableReload();
            }
        });
    }
    function add() {
        let width = $('html').width();
        let height = $('html').height();
        width = 480;
        height = 500;
        layer.open({
            id: 'showLayer',
            type: 2,
            title: '添加用户',
            shadeClose: true,
            shade: false,
            area: [width+'px', height+'px'],
            content: '${home}/sysUser/add',
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
                url: "${home}/sysUser/delete/" + id ,
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

    function plus(userId,userName) {
        layer.open({
            id: 'showLayer',
            type: 2,
            title: userName+'用户积分上分',
            shadeClose: true,
            shade: false,
            area: ['380px', '500px'],
            content: '${home}/recharge/plusForm?userId='+userId,
            end: function (index) {
                tableReload();
            }
        });
    }
    function reduce(userId,userName) {
        layer.open({
            id: 'showLayer',
            type: 2,
            title: userName+'用户积分下分',
            shadeClose: true,
            shade: false,
            area: ['380px', '500px'],
            content: '${home}/recharge/reduceForm?userId='+userId,
            end: function (index) {
                tableReload();
            }
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
        <button class="layui-btn layui-btn-normal" lay-event="add">添加用户</button>
        <button class="layui-btn layui-btn-warm" lay-event="update">编辑</button>
        <button class="layui-btn layui-btn-danger" lay-event="delete">删除</button>
    </div>
</script>
<script type="text/html" id="barDemo">
    <button class="layui-btn layui-btn-normal" lay-event="plus" >上分</button>
    <button class="layui-btn layui-btn-normal" lay-event="reduce">下分</button>
    <button class="layui-btn layui-btn-normal" lay-event="detail">上下分明细</button>
    <button class="layui-btn layui-btn-normal" lay-event="lotteryDetail">投注明细</button>
</script>
</body>
<style>
    .layui-table-cell{
        text-overflow: fade;
    }
</style>
</html>
