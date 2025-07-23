/*    */
package com.bss.utils;

import java.util.Objects;

/*    */
/*    */ public class R<T>
        /*    */ {
    /*    */   private Integer code;
    /*    */   private String msg;
    /*    */   private T data;

    /*    */
    /*    */
    public R() {
    }

    /*    */
    /*    */
    public R(T data) {
        /* 44 */
        this.data = data;
        /*    */
    }

    /*    */
    /*    */
    public static com.bss.utils.R success() {
        /* 48 */
        com.bss.utils.R result = new com.bss.utils.R();
        /* 49 */
        result.setCode(Integer.valueOf(20000));
        /* 50 */
        result.setMsg("请求成功");
        /*    */
        /* 52 */
        return result;
        /*    */
    }

    /*    */
    /*    */
    public static com.bss.utils.R success(String msg) {
        /* 56 */
        com.bss.utils.R result = new com.bss.utils.R();
        /* 57 */
        result.setCode(Integer.valueOf(20000));
        /* 58 */
        result.setMsg(msg);
        /*    */
        /* 60 */
        return result;
        /*    */
    }

    /*    */
    /*    */
    public static com.bss.utils.R fail(String msg) {
        /* 64 */
        com.bss.utils.R result = new com.bss.utils.R();
        /* 65 */
        result.setCode(Integer.valueOf(100000));
        /* 66 */
        result.setMsg(msg);
        /*    */
        /* 68 */
        return result;
        /*    */
    }

    /*    */
    /*    */
    public static <T> com.bss.utils.R<T> success(T data) {
        /* 72 */
        com.bss.utils.R<T> result = new com.bss.utils.R<>(data);
        /* 73 */
        result.setCode(Integer.valueOf(20000));
        /* 74 */
        result.setMsg("请求成功");
        /*    */
        /* 76 */
        return result;
        /*    */
    }

    /*    */
    /*    */
    public boolean equals(Object o) {
        /* 10 */
        if (o == this) return true;
        if (!(o instanceof com.bss.utils.R)) return false;
        com.bss.utils.R<?> other = (com.bss.utils.R) o;
        if (!other.canEqual(this)) return false;
        Object this$code = getCode(), other$code = other.getCode();
        if (!Objects.equals(this$code, other$code)) return false;
        Object this$msg = getMsg(), other$msg = other.getMsg();
        if (!Objects.equals(this$msg, other$msg)) return false;
        Object this$data = getData(), other$data = other.getData();
        return !(!Objects.equals(this$data, other$data));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.utils.R;
    }


    public String toString() {
        return "R(code=" + getCode() + ", msg=" + getMsg() + ", data=" + getData() + ")";
    }

    /*    */
    /*    */
    /*    */
    /*    */
    /*    */
    /*    */
    /*    */
    public Integer getCode() {
        /* 18 */
        return this.code;
        /*    */
    }

    /*    */
    /*    */
    public void setCode(Integer code) {
        /* 22 */
        this.code = code;
        /*    */
    }

    /*    */
    /*    */
    public String getMsg() {
        /* 26 */
        return this.msg;
        /*    */
    }

    /*    */
    /*    */
    public void setMsg(String msg) {
        /* 30 */
        this.msg = msg;
        /*    */
    }

    /*    */
    /*    */
    public T getData() {
        /* 34 */
        return this.data;
        /*    */
    }

    /*    */
    /*    */
    public void setData(T data) {
        /* 38 */
        this.data = data;
        /*    */
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bs\\utils\R.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */