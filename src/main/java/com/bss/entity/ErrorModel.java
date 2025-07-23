/*    */
package com.bss.entity;

import java.util.Objects;

/*    */
/*    */
/*    */
/*    */
/*    */
/*    */
/*    */ public class ErrorModel
        /*    */ {
    /*    */   private Integer code;
    /*    */   private String msg;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.ErrorModel)) return false;
        com.bss.entity.ErrorModel other = (com.bss.entity.ErrorModel) o;
        if (!other.canEqual(this)) return false;
        Object this$code = getCode(), other$code = other.getCode();
        if (!Objects.equals(this$code, other$code)) return false;
        Object this$msg = getMsg(), other$msg = other.getMsg();
        return !(!Objects.equals(this$msg, other$msg));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.ErrorModel;
    }



    public String toString() {
        return "ErrorModel(code=" + getCode() + ", msg=" + getMsg() + ")";
    }

    /*    */
    /*    */
    public Integer getCode() {
        /* 17 */
        return this.code;
        /*    */
    }

    /*    */
    /*    */
    public void setCode(Integer code) {
        /* 14 */
        this.code = code;
    }

    public String getMsg() {
        /* 19 */
        return this.msg;
        /*    */
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\ErrorModel.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */