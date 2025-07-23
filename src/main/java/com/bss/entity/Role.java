/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;

import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("role")
/*    */ public class Role implements Serializable {
    /*    */   private static final long serialVersionUID = 1L;
    /*    */   private Integer id;
    /*    */   private String name;
    /*    */   private String sn;
    /*    */   private String sketch;
    /*    */   private String createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Role)) return false;
        com.bss.entity.Role other = (com.bss.entity.Role) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$sn = getSn(), other$sn = other.getSn();
        if (!Objects.equals(this$sn, other$sn)) return false;
        Object this$sketch = getSketch(), other$sketch = other.getSketch();
        if (!Objects.equals(this$sketch, other$sketch)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Role;
    }


    public String toString() {
        return "Role(id=" + getId() + ", name=" + getName() + ", sn=" + getSn() + ", sketch=" + getSketch() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 17 */
        return this.id;
        /*    */
    }

    /*    */
    /* 14 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        /* 19 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSn() {
        /* 21 */
        return this.sn;
        /*    */
    }

    public void setSn(String sn) {
        this.sn = sn;
    }

    public String getSketch() {
        /* 23 */
        return this.sketch;
        /*    */
    }

    public void setSketch(String sketch) {
        this.sketch = sketch;
    }

    public String getCreateTime() {
        /* 25 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Role.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */