/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;
/*    */ import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("permission")
/*    */ public class Permission implements Serializable {
    /*    */   private static final long serialVersionUID = 1L;
    /*    */   private Integer id;
    /*    */   private String name;
    /*    */   private String resource;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Permission)) return false;
        com.bss.entity.Permission other = (com.bss.entity.Permission) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$resource = getResource(), other$resource = other.getResource();
        return !(!Objects.equals(this$resource, other$resource));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Permission;
    }


    public String toString() {
        return "Permission(id=" + getId() + ", name=" + getName() + ", resource=" + getResource() + ")";
    }

    /*    */
    public Integer getId() {
        /* 16 */
        return this.id;
        /*    */
    }

    /*    */
    /*    */
    public void setId(Integer id) {
        /* 14 */
        this.id = id;
    }

    public String getName() {
        /* 18 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getResource() {
        /* 20 */
        return this.resource;
        /*    */
    }

    public void setResource(String resource) {
        this.resource = resource;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Permission.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */