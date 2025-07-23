/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;
/*    */ import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("exception_log")
/*    */ public class ExceptionLog implements Serializable {
    /*    */   private static final long serialVersionUID = 1L;
    /*    */   private Object id;
    /*    */   private String exceptionName;
    /*    */   private String exceptionMessage;
    /*    */   private String createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.ExceptionLog)) return false;
        com.bss.entity.ExceptionLog other = (com.bss.entity.ExceptionLog) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$exceptionName = getExceptionName(), other$exceptionName = other.getExceptionName();
        if (!Objects.equals(this$exceptionName, other$exceptionName))
            return false;
        Object this$exceptionMessage = getExceptionMessage(), other$exceptionMessage = other.getExceptionMessage();
        if (!Objects.equals(this$exceptionMessage, other$exceptionMessage))
            return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.ExceptionLog;
    }


    public String toString() {
        return "ExceptionLog(id=" + getId() + ", exceptionName=" + getExceptionName() + ", exceptionMessage=" + getExceptionMessage() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    public Object getId() {
        /* 16 */
        return this.id;
        /*    */
    }

    /*    */
    /* 14 */
    public void setId(Object id) {
        this.id = id;
    }

    public String getExceptionName() {
        /* 18 */
        return this.exceptionName;
        /*    */
    }

    public void setExceptionName(String exceptionName) {
        this.exceptionName = exceptionName;
    }

    public String getExceptionMessage() {
        /* 20 */
        return this.exceptionMessage;
        /*    */
    }

    public void setExceptionMessage(String exceptionMessage) {
        this.exceptionMessage = exceptionMessage;
    }

    public String getCreateTime() {
        /* 22 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\ExceptionLog.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */